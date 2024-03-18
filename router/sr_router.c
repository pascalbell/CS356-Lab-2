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
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_arpcache.c"
#include "sr_utils.h"
#include "vnscommand.h"

 #define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

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
                    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)pkt->buf;            
                    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, pkt->iface)->addr, ETHER_ADDR_LEN);

                    int send_result = sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                    if (send_result) {
                        fprintf(stderr, "Failed to send packet from ARP request queue\n");
                    } else {
                        printf("Packet sent from ARP request queue\n");
                    }
                    pkt = pkt->next;
                }
                sr_arpreq_destroy(&(sr->cache), req);                 /* Destroy the request */
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
                    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)pkt->buf;            
                    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, pkt->iface)->addr, ETHER_ADDR_LEN);

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
        uint16_t checksum = cksum((uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t));
        printf("Checksum result: 0x%04x\n", checksum);
        if (checksum != 0 && checksum != 0xFFFF) {
            fprintf(stderr, "IP header checksum incorrect\n");
            return;
        }
        printf("checksum passed\n");

        /* Check if the IP packet is destined for this router */
        struct sr_if *iface = sr->if_list;
        while (iface) {
            /* Error with this while loop */
            if (iface->ip == ip_hdr->ip_dst) {
                printf("Received IP packet destined for router\n");

                /* Check if the packet is ICMP */
                if (ip_hdr->ip_p == ip_protocol_icmp) {
                    /* Extract ICMP and Ethernet header */
                    struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)((uint8_t *)ip_hdr + sizeof(sr_ip_hdr_t));
                    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;

                    /* Check if it is an ICMP echo request */
                    if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
                        printf("Received ICMP echo request\n");

                        /* Allocate memory for the new ICMP echo reply packet */
                        uint8_t *icmp_packet = (uint8_t *)malloc(len);
                        int i =0;
                        for (i; i<len; i++) {
                            icmp_packet[i] = packet[i];
                        }

                        /* Get interface */
                        struct sr_if *rec_iface = sr_get_interface(sr, interface);
                        if (!rec_iface) {
                            fprintf(stderr, "No interface to send ICMP");
                            return;
                        }

                        /* Ethernet header */
                        sr_ethernet_hdr_t *ethernet_hdr_new = (sr_ethernet_hdr_t *)icmp_packet;
                        memcpy(ethernet_hdr_new->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
                        memcpy(ethernet_hdr_new->ether_shost, rec_iface->addr, ETHER_ADDR_LEN);
                        ethernet_hdr->ether_type = htons(ethertype_ip);

                        /* IP header */
                        sr_ip_hdr_t *ip_hdr_new = (sr_ip_hdr_t *)(icmp_packet+sizeof(sr_ethernet_hdr_t));
                        ip_hdr_new->ip_p = ip_protocol_icmp;
                        ip_hdr_new->ip_tos = 0;
                        ip_hdr_new->ip_ttl = 64; 
                        ip_hdr_new->ip_sum = 0;
                        ip_hdr_new->ip_dst = ip_hdr->ip_src;
                        ip_hdr_new->ip_src = ip_hdr->ip_dst;
                        ip_hdr_new->ip_sum = cksum((uint8_t *)ip_hdr_new, sizeof(sr_ip_hdr_t));

                        /* ICMP header */
                        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
                        icmp_hdr->icmp_code = 0;
                        icmp_hdr->icmp_type = 0;
                        icmp_hdr->icmp_sum = 0;
                        icmp_hdr->icmp_sum = cksum((uint8_t *) icmp_hdr, sizeof(sr_icmp_hdr_t));

                        /* Send packet */
                        int send_result = sr_send_packet(sr, icmp_packet, len, interface);
                        free(icmp_packet);
                        if (send_result != 0 ) {
                            fprintf(stderr, "Failed to send ICMP echo reply packet\n");
                       } else {
                           printf("ICMP echo reply packet sent\n");
                       }
                       return;
                    }
                } else {   /* if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17) */
                    printf("Received packet with TCP or UDP payload\n");

                    /* Malloc space for ICMP return packet */
                    unsigned int icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                    uint8_t *icmp_port_unreachable_pkt = (uint8_t *)malloc(icmp_packet_len);

                    /* Get interface */
                    struct sr_if *rec_iface = sr_get_interface(sr, interface);
                    if (!rec_iface) {
                        fprintf(stderr, "No interface to send ICMP");
                        return;
                    }

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
                    icmp_hdr->icmp_code = 3; /* Port Unreachable */
                    icmp_hdr->icmp_sum = 0; /* Checksum (0 for now) */
                    icmp_hdr->unused = 0;
                    icmp_hdr->next_mtu = 0;
                    memcpy(icmp_hdr->data, icmp_ip_hdr_original, ICMP_DATA_SIZE);
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); /* Calculate ICMP checksum */

                    /* Send ICMP port unreachable packet */
                    int send_result = sr_send_packet(sr, icmp_port_unreachable_pkt, icmp_packet_len, interface);
                    free(icmp_port_unreachable_pkt); /* Free memory allocated for ICMP packet */

                    if (send_result != 0) {
                        fprintf(stderr, "Failed to send ICMP port unreachable packet\n");
                        /* Handle error, e.g., resend packet or notify user */
                    } else {
                        printf("ICMP port unreachable packet sent\n");
                    }
                }
                return; /* Exit function after processing IP packet */
            }
            if (!iface->next) {
                break;
            }
            iface = iface->next;
        }

        /* else if packet is for a different router, follow steps and add to ARP request queue */
        printf("IP packet not destined for this router");
        
        /* Decrement the TTL by 1 */
        ip_hdr->ip_ttl -= 1;
        if (ip_hdr->ip_ttl == 0) {             
            /* Send Time Exceeded ICMP message */

            /* Malloc space for ICMP return packet */
            unsigned int icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *icmp_port_unreachable_pkt = (uint8_t *)malloc(icmp_packet_len);

            /* Get interface */
            struct sr_if *rec_iface = sr_get_interface(sr, interface);
            if (!rec_iface) {
                fprintf(stderr, "No interface to send ICMP");
                return;
            }

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
            icmp_hdr->icmp_type = 11; /* Destination Unreachable */
            icmp_hdr->icmp_code = 0; /* Port Unreachable */
            icmp_hdr->icmp_sum = 0; /* Checksum (0 for now) */
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, icmp_ip_hdr_original, ICMP_DATA_SIZE);
            icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); /* Calculate ICMP checksum */

            /* Send ICMP port unreachable packet */
            int send_result = sr_send_packet(sr, icmp_port_unreachable_pkt, icmp_packet_len, interface);
            free(icmp_port_unreachable_pkt); /* Free memory allocated for ICMP packet */

            if (send_result != 0) {
                fprintf(stderr, "Failed to send ICMP time limit exceeded packet\n");
                /* Handle error, e.g., resend packet or notify user */
            } else {
                printf("ICMP time limit exceeded sent\n");
            }
            return;
        }

        /* Recompute checksum if TTL != 0 */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));


        /* Iterate through the routing table and find longest match */
        struct sr_rt* longest_match = NULL;
        struct sr_rt* rt_entry = sr->routing_table;
        while (rt_entry) {
            if (rt_entry->dest.s_addr == ip_hdr->ip_dst) {
                if (!longest_match) {
                    longest_match = rt_entry;
                } else {
                    struct sr_if* this_if = sr_get_interface(sr, rt_entry->interface);
                    struct sr_if* longest_if = sr_get_interface(sr, longest_match->interface);
                    if (MIN(this_if->mask, ~(this_if->ip ^ ip_hdr->ip_dst)) > MIN(longest_if->mask, ~(longest_if->ip ^ ip_hdr->ip_dst))) {
                        longest_match = rt_entry;
                    }
                }
            }
            rt_entry = rt_entry->next;
        }

        if (longest_match) {
            /* Found the longest prefix match */
            printf("Longest prefix match found in routing table\n");
            sr_print_routing_entry(longest_match);

            struct sr_if* outgoing_iface = sr_get_interface(sr, longest_match->interface);

            /* Check if the next hop IP is in the ARP cache */
            struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, longest_match->gw.s_addr);
            if (arp_entry) {
                printf("Found NextHop MAC");
                
                /* Use the MAC address mapping in the ARP cache entry to send the packet */
                uint8_t *eth_ip_frame = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len));

                /* Create the Ethernet header */
                sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)eth_ip_frame;
                memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
                memcpy(ethernet_hdr->ether_shost, outgoing_iface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
                ethernet_hdr->ether_type = htons(ethertype_ip);

                /* Attach the IP payload */
                memcpy(eth_ip_frame + sizeof(sr_ethernet_hdr_t), ip_hdr, ntohs(ip_hdr->ip_len));

                int send_result = sr_send_packet(sr, eth_ip_frame, sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len), outgoing_iface->name);
                free(eth_ip_frame);
                if (send_result != 0) {
                    fprintf(stderr, "Failed to send packet to next hop IP\n");
                    /* Handle error, e.g., resend packet or notify user */
                } else {
                    printf("Packet sent to next hop IP\n");
                }
                /* sr_arpreq_destroy(&(sr->cache), arp_entry); */ /* Free the ARP cache entry */
            } else {
                struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), longest_match->gw.s_addr, packet, len, longest_match->interface);
                printf("Packet queued in ARP request queue\n");
                send_arp_request(sr, outgoing_iface, longest_match->gw.s_addr, packet, len);
            }              
        } else {
            /* No matching entry found in routing table */
            fprintf(stderr, "No matching entry found in routing table for destination IP\n");
            /* send ICMP destination net unreachable (type 3, code 0) */
            /* Malloc space for ICMP return packet */
            unsigned int icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *icmp_port_unreachable_pkt = (uint8_t *)malloc(icmp_packet_len);

            /* Get interface */
            struct sr_if *rec_iface = sr_get_interface(sr, interface);
            if (!rec_iface) {
                fprintf(stderr, "No interface to send ICMP");
                return;
            }

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
            icmp_hdr->icmp_code = 0; /* Port Unreachable */
            icmp_hdr->icmp_sum = 0; /* Checksum (0 for now) */
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, icmp_ip_hdr_original, ICMP_DATA_SIZE);
            icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); /* Calculate ICMP checksum */

            /* Send ICMP port unreachable packet */
            int send_result = sr_send_packet(sr, icmp_port_unreachable_pkt, icmp_packet_len, interface);
            free(icmp_port_unreachable_pkt); /* Free memory allocated for ICMP packet */

            if (send_result != 0) {
                fprintf(stderr, "Failed to send ICMP port unreachable packet\n");
                /* Handle error, e.g., resend packet or notify user */
            } else {
                printf("ICMP port unreachable packet sent\n");
            }
            return;
        }


    }

}/* end sr_ForwardPacket */