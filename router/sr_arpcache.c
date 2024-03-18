#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"

void send_arp_request(struct sr_instance* instance, struct sr_if* interface, uint32_t target_ip, uint8_t *original_packet, unsigned int original_packet_len) {
    /* Allocate memory for the ARP request */
    uint8_t* arp_request_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

    /* Create broadcast address to store in the Ethernet header */
    uint8_t broadcast_address[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    /* Populate the Ethernet header */
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)arp_request_packet;
    memcpy(ethernet_header->ether_dhost, broadcast_address, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    ethernet_header->ether_type = htons(ethertype_arp);

    /* Populate the ARP request header */
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(arp_request_packet + sizeof(sr_ethernet_hdr_t));
    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_pro = htons(ethertype_ip);
    arp_header->ar_hln = ETHER_ADDR_LEN;
    arp_header->ar_pln = sizeof(uint32_t);
    arp_header->ar_op = htons(arp_op_request);
    memcpy(arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN);
    arp_header->ar_sip = interface->ip;
    memset(arp_header->ar_tha, 0x00, ETHER_ADDR_LEN);
    arp_header->ar_tip = target_ip;

    /* Send the ARP request */
    if (sr_send_packet(instance, arp_request_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface->name) < 0) {
        fprintf(stderr, "Error: Failed to send ARP request\n");
    } else {
        printf("ARP request sent\n");
    }
    /* Queue the request */
    sr_arpcache_queuereq(&instance->cache, target_ip, original_packet, original_packet_len, interface->name);

    /* Free the memory allocated for the ARP request packet */
    free(arp_request_packet);
}

/* IMPLEMENT: 
    if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++
*/
void handle_arpreq(struct sr_arpreq *req, struct sr_instance *sr, struct sr_arpcache *cache) {
    time_t current_time = time(NULL);
    if (difftime(current_time, req->sent) > 1.0) {
        
       struct sr_packet *current_packet = req->packets;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(current_packet + sizeof(sr_ethernet_hdr_t));

        if(req->times_sent >= 5) {
            /* if more than 5 requests sent, send ICMP for each packet */
            while(current_packet) {
                uint8_t* packet = current_packet->buf;
                char* interface = current_packet->iface;
                
                /* Malloc space for ICMP return packet */
                unsigned int icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                uint8_t *icmp_port_unreachable_pkt = (uint8_t *)malloc(icmp_packet_len);
                struct sr_if *rec_iface = sr_get_interface(sr, interface);

                /* Fill in Ethernet header */
                sr_ethernet_hdr_t *icmp_eth_hdr = (sr_ethernet_hdr_t *)icmp_port_unreachable_pkt;
                sr_ethernet_hdr_t *icmp_eth_hdr_original = (sr_ethernet_hdr_t *)packet;
                memcpy(icmp_eth_hdr->ether_dhost, icmp_eth_hdr_original->ether_shost, ETHER_ADDR_LEN); /* Destination MAC = Source MAC */
                memcpy(icmp_eth_hdr->ether_shost, icmp_eth_hdr_original->ether_dhost, ETHER_ADDR_LEN); /* Source MAC = Interface MAC */
                icmp_eth_hdr->ether_type = htons(ethertype_ip); /* IP type */

                /* Fill in IP header */
                sr_ip_hdr_t *icmp_ip_hdr = (sr_ip_hdr_t *)(icmp_port_unreachable_pkt + sizeof(sr_ethernet_hdr_t));
                sr_ip_hdr_t *icmp_ip_hdr_original = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
                memcpy(icmp_ip_hdr, icmp_ip_hdr_original, sizeof(sr_ip_hdr_t));
                icmp_ip_hdr->ip_tos = 0; /* Type of Service */
                icmp_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); /* Total length */
                icmp_ip_hdr->ip_id = htons(0); /* Identification */
                icmp_ip_hdr->ip_off = htons(IP_DF); /* Flags and Fragment Offset (Don't Fragment) */
                icmp_ip_hdr->ip_ttl = 64; /* Time to Live */
                icmp_ip_hdr->ip_p = ip_protocol_icmp; /* ICMP Protocol */
                icmp_ip_hdr->ip_sum = 0; /* Checksum (0 for now) */
                icmp_ip_hdr->ip_src = rec_iface->ip; /* Source IP = Destination IP of the original packet */
                icmp_ip_hdr->ip_dst = icmp_ip_hdr_original->ip_src; /* Destination IP = Source IP of the original packet */
                icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, sizeof(sr_ip_hdr_t)); /* Calculate IP checksum */

                /* Fill in ICMP header */
                sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_port_unreachable_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                icmp_hdr->icmp_type = 3; /* Destination Unreachable */
                icmp_hdr->icmp_code = 1; /* Port Unreachable */
                icmp_hdr->icmp_sum = 0; /* Checksum (0 for now) */
                icmp_hdr->unused = 0;
                icmp_hdr->next_mtu = 0;
                memcpy(icmp_hdr->data, icmp_ip_hdr_original, ICMP_DATA_SIZE);
                icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); /* Calculate ICMP checksum */

                /* Send ICMP destination unreachable packet */
                int send_result = sr_send_packet(sr, icmp_port_unreachable_pkt, icmp_packet_len, interface);
                free(icmp_port_unreachable_pkt); /* Free memory allocated for ICMP packet */

                if (send_result != 0) {
                    fprintf(stderr, "Failed to send ICMP Destination host unreachable\n");
                    /* Handle error, e.g., resend packet or notify user */
                } else {
                    printf("ICMP Destination host unreachable sent\n");
                }
                current_packet = current_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), req);
        }
        else {
            /* send ARP request */
            send_arp_request(sr, current_packet->iface, ip_hdr->ip_dst, current_packet, current_packet->len);
            req->sent = current_time;
            req->times_sent++;
        }
    }
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* for each request on sr->cache.requests:
           handle_arpreq(request) */

    struct sr_arpreq *req = sr->cache.requests;
    while (req) {
        handle_arpreq(req, sr, &sr->cache);
        req = req->next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = NULL;
        if (req->packets == NULL){
            req->packets = new_pkt;
        }
        else{
            struct sr_packet *p = req->packets;
            while(p->next != NULL)
                p = p->next;
            p->next = new_pkt;
        }
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

