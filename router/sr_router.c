/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);           /* print the packet header */

    if (len < sizeof(sr_ethernet_hdr_t)) {                          /* packet is too short */
            fprintf(stderr, "Packet is too short for Ethernet header\n");
            return;
    }

    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;  /* Cast ethernet header */
    
    /* Check if the packet is an ARP packet, TEST THIS*/
    if (ntohs(ethernet_hdr->ether_type) == ethertype_arp) {
      printf("Detected ARP Header\n");
      /* Extract the ARP header */
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      /* Check if it's an ARP reply */
      if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
          printf("Received ARP reply\n");
          
          /* Add to ARP cache and print out cache*/
          struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
          sr_arpcache_dump(&(sr->cache));

          if (req) {
                /* Send packets if the there are requests waiting on this MAC */
                struct sr_packet *pkt = req->packets;
                while (pkt) {
                    /* Copy sender hardware addr into the buffer and send back*/
                    sr_ethernet_hdr_t* eth_hdr = pkt->buf;            
                    strncpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

                    int send_result = sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                    if (send_result) {
                        fprintf(stderr, "Failed to send packet from ARP request queue\n");
                    } else {
                        printf("Packet sent from ARP request queue\n");
                    }
                    pkt = pkt->next;
                }
                sr_arpreq_destroy(&sr->cache, req);                 /* Destroy the request */
          } else {
              fprintf(stderr, "No requests waiting on this MAC \n");
          }
        } else if (ntohs(arp_hdr->ar_op) == arp_op_request) { /* If not reply, then its ARP request */
            printf("Received ARP Request");

            /* insert into the cache and print*/
            struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
            sr_arpcache_dump(&(sr->cache));

            if (req) {
                /* Send packets if the there are requests waiting on this MAC */
                struct sr_packet *pkt = req->packets;
                while (pkt) {
                    /* Copy sender hardware addr into the buffer and send back*/
                    sr_ethernet_hdr_t* eth_hdr = pkt->buf;            
                    strncpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

                    int send_result = sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                    if (send_result) {
                        fprintf(stderr, "Failed to send packet from ARP request queue\n");
                    } else {
                        printf("Packet sent from ARP request queue\n");
                    }
                    pkt = pkt->next;
                }
                sr_arpreq_destroy(&sr->cache, req);                 /* Destroy the request */
            } else {
                fprintf(stderr, "No requests waiting on this MAC \n");
            }
            
            /* Now you have to check if the request is destined to its own interface and 
                send the ARP reply with the MAC header back if so
            */
            struct sr_if *iface = sr->if_list;
            while (iface) {
                if (iface->ip == arp_hdr->ar_tip) {             /* If ARP IP matches interface IP */
                    printf("ARP request is for this router's IP\n");

                    /* Construct ARP reply packet */
                    uint8_t *arp_reply_pkt = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
                    sr_ethernet_hdr_t *arp_reply_eth_hdr = (sr_ethernet_hdr_t *)arp_reply_pkt;
                    sr_arp_hdr_t *arp_reply_hdr = (sr_arp_hdr_t *)(arp_reply_pkt + sizeof(sr_ethernet_hdr_t));
                    
                    /* Fill in Ethernet header - strncpy or memcpy?? */
                    memcpy(arp_reply_eth_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN); /* Destination MAC */
                    memcpy(arp_reply_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN); /* Source MAC */
                    arp_reply_eth_hdr->ether_type = htons(ethertype_arp); /* ARP type */
                    
                    /* Fill in ARP header */
                    arp_reply_hdr->ar_hrd = arp_hdr->ar_hrd; /* Hardware type */
                    arp_reply_hdr->ar_pro = arp_hdr->ar_pro; /* Protocol type */
                    arp_reply_hdr->ar_hln = arp_hdr->ar_hln; /* Hardware address length */
                    arp_reply_hdr->ar_pln = arp_hdr->ar_pln; /* Protocol address length */
                    arp_reply_hdr->ar_op = htons(arp_op_reply); /* ARP reply opcode */
                    memcpy(arp_reply_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN); /* Sender hardware address (MAC) */
                    arp_reply_hdr->ar_sip = iface->ip; /* Sender protocol address (IP) */
                    memcpy(arp_reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); /* Target hardware address (MAC) */
                    arp_reply_hdr->ar_tip = arp_hdr->ar_sip; /* Target protocol address (IP) */

                    /* Send ARP reply packet */
                    int send_result = sr_send_packet(sr, arp_reply_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface->name);
                    free(arp_reply_pkt); /* Free memory allocated for packet */
                    sr_arpreq_destroy(&(sr->cache), req);
                    if (send_result != 0) {
                        fprintf(stderr, "Failed to send ARP reply packet\n");
                        /* Handle error, e.g., resend packet or notify user */
                    } else {
                        printf("ARP reply sent\n");
                    }
                    break;
                }
                iface = iface->next;
            }
        }               /* THIS PART IS COMPLETE AND WORKS */
    } else if (ntohs(ethernet_hdr->ether_type) == ethertype_ip) {       /* Check if the packet is IP packet */
        printf("Detected IP Header\n");

        print_hdrs(packet, len);

        /* Check that packet is right length */
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            fprintf(stderr, "Packet is too short for IP header\n");
            return;
        }

        /* Extract header as IP */
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        
        /* perform checksum, check not equal to zero or 0xFFFF for bad checksum */
        uint16_t checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        printf("Checksum result: 0x%04x\n", checksum);
        if (checksum != 0 && checksum != 0xFFFF) {
        fprintf(stderr, "IP header checksum incorrect\n");
            return;
        }

        /* Check if the IP packet is destined for this router */
        struct sr_if *iface = sr->if_list;
        while (iface) {
            if (iface->ip == ip_hdr->ip_dst) {
                printf("Received IP packet destined for router\n");

                /* Check if the packet is ICMP echo request */
                if (ip_hdr->ip_p == ip_protocol_icmp) {
                    /* Calculate ICMP header offset */
                    uint8_t *icmp_pkt = packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); /* ICMP packet starts after IP header */

                    /* Extract ICMP header */
                    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)icmp_pkt;

                    /* Check if it is an ICMP echo request */
                    if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
                        printf("Received ICMP echo request\n");


                        /* construct echo reply and copy into the packet data */
                        uint8_t* icmp_echo_reply = (uint8_t*)malloc(len);
                        int i = 0;
                        for (i = 0; i < len; i++) {
                            icmp_echo_reply[i] = packet[i];
                        }

                        /*
                        1. make a new packet, cast it to ethernet packet, set the ethernet header like mac address
                        2. set the IP packet field, checksum - size of IP header new packet
                        3. Set ICMP fields
                        
                        
                        ICMP packet fomat: Send ICMP with normal IP header, then ICMP header, then IP header of messed up packet, then payload of original
                        */
                        
                        /* construct ICMP echo reply packet */
                        uint8_t *icmp_reply_pkt = malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len));
                        memcpy(icmp_reply_pkt, packet, sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len)); /* Copy the original packet */
                        sr_ip_hdr_t *icmp_reply_ip_hdr = (sr_ip_hdr_t *)(icmp_reply_pkt + sizeof(sr_ethernet_hdr_t));
                        sr_icmp_hdr_t *icmp_reply_icmp_hdr = (sr_icmp_hdr_t *)(icmp_reply_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                        /* Fill in the ICMP echo reply header */
                        icmp_reply_icmp_hdr->icmp_type = 0; /* ICMP echo reply */
                        icmp_reply_icmp_hdr->icmp_code = 0;
                        icmp_reply_icmp_hdr->icmp_sum = 0; /* Clear checksum field before computing checksum */
                        icmp_reply_icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_reply_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)); /* Compute ICMP checksum */

                        /* FILL IN OTHER FIELDS HERE */

                        /* Send ICMP echo reply packet */
                        int send_result = sr_send_packet(sr, icmp_reply_pkt, sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len), interface);
                        if (send_result != 0) {
                            fprintf(stderr, "Failed to send ICMP echo reply packet\n");
                            /* Handle error, e.g., resend packet or notify user */
                        } else {
                            printf("ICMP echo reply sent\n");
                        }

                        free(icmp_reply_pkt); /* Free memory allocated for packet */
                    }
                } else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17) {
                    /* If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host. Otherwise, ignore the packet. Packets destined elsewhere should be forwarded using your normal forwarding logic. */
                }
                return; /* Exit function after processing IP packet */
            }
            iface = iface->next;
        }

        /* else if packet is for a different router, follow steps and add to ARP request queue */
        printf("IP packet not destined for this router");
        
        /* Decrement the TTL by 1 and recomput checksum*/
        ip_hdr->ip_ttl -= 1;
        if (ip_hdr->ip_ttl == 0) {
            /* Send ICMP with normal IP header, then ICMP header, then IP header of messed up packet, then payload of original*/
        }

        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /* Find the longest prefix match */
        struct in_addr dest_ip_addr;
        dest_ip_addr.s_addr = ip_hdr->ip_dst;  // Assuming ip_hdr->ip_dst is a uint32_t representing the destination IP address
        struct sr_rt* longest_match_entry = find_longest_prefix_match(sr, dest_ip_addr);
        if (longest_match_entry) {
            /* Found the longest prefix match */
            printf("Longest prefix match found in routing table\n");

            /* Now you can proceed with forwarding the packet based on the longest match entry */
            /* Code to forward packet using the information in longest_match_entry */

            /* Use isntructions on lab2 */
        } else {
            /* No matching entry found in routing table */
            fprintf(stderr, "No matching entry found in routing table for destination IP\n");
            /* send ICMP destination net unreachable (type 3, code 0) */
        }


    }

}/* end sr_ForwardPacket */

/* Function to find the longest prefix match */
struct sr_rt* find_longest_prefix_match(struct sr_instance* sr, struct in_addr dest_ip) {
    struct sr_rt* longest_match = NULL;
    int max_prefix_length = -1;

    /* Iterate through the routing table */
    struct sr_rt* rt_entry = sr->routing_table;
    while (rt_entry) {
        /* Calculate the prefix length */
        struct in_addr masked_dest = {dest_ip.s_addr & rt_entry->mask.s_addr};
        int prefix_length = 0;
        uint32_t mask = ntohl(rt_entry->mask.s_addr);
        while (mask) {
            mask >>= 1;
            prefix_length++;
        }

        /* Check if the current entry has a longer prefix match */
        if ((masked_dest.s_addr == rt_entry->dest.s_addr) && (prefix_length > max_prefix_length)) {
            max_prefix_length = prefix_length;
            longest_match = rt_entry;
        }

        /* Move to the next entry */
        rt_entry = rt_entry->next;
    }

    return longest_match;
}