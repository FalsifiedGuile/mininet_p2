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

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);
int handle_arpreq_pkt(struct sr_instance *sr, uint32_t arp_request_ip_dest, struct sr_if *dest_if);
void handle_icmp_host_unreachable_pkt(struct sr_instance *sr, struct sr_packet *icmp_pkt);

void sr_arpcache_sweepreqs(struct sr_instance *sr) {
  struct sr_arpreq *current_request, *next = NULL;
  if ((current_request = sr->cache.requests) == NULL) {
  }
  while(current_request) {
    printf("looking through requests ---- \n");
    next = current_request->next;
    handle_arpreq(sr, current_request);
    current_request = next;
  }
  /*
  for (current_request = sr->cache.requests; current_request != NULL; current_request = *current_request->next) {
    handle_arpreq(sr, current_request);

  }*/
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
  time_t now = time(NULL);
  if (difftime(now, req->sent) > 1.0){
    if (req->times_sent >= 5){
       /* mMybe over allocation */
       printf("sending icmp host unreachable------\n");
       struct sr_packet *icmp_pkt, *next = NULL;
       icmp_pkt = req->packets;
       while(icmp_pkt) {
         next = icmp_pkt->next;
         handle_icmp_host_unreachable_pkt(sr, icmp_pkt);
         icmp_pkt = next;
       }
      sr_arpreq_destroy(&(sr->cache), req);
    } else {
      struct sr_if *dest_if = 0;
      dest_if = sr_get_interface(sr, req->packets->iface);

      if (handle_arpreq_pkt(sr, req->ip, dest_if) < 0) {
        printf("error in sending the arpreq_pkt from queue\n");
      }
      req->sent = time(NULL);
      req->times_sent++;
    }

  }
}

int handle_arpreq_pkt(struct sr_instance *sr, uint32_t arp_request_ip_dest, struct sr_if *dest_if){
  struct sr_ethernet_hdr* eth_hdr = 0;
  struct sr_arp_hdr* arp_hdr = 0;
  unsigned int pkt_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
  uint8_t* arp_pkt = malloc(pkt_len);

  eth_hdr = (struct sr_ethernet_hdr*)arp_pkt;
  memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, dest_if->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  arp_hdr = (struct sr_arp_hdr *)(sizeof(struct sr_ethernet_hdr) + arp_pkt);

  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = sizeof(uint32_t);
  arp_hdr->ar_op = htons(arp_op_request);
  memcpy(arp_hdr->ar_sha, dest_if->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = dest_if->ip;
  memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
  arp_hdr->ar_tip =  arp_request_ip_dest;

  int error_chk;
  printf("dest_if is %s -------------------------\n", dest_if->name);
  error_chk = sr_send_packet(sr, arp_pkt, pkt_len, dest_if->name);

  return error_chk;
}

void handle_icmp_host_unreachable_pkt(struct sr_instance *sr, struct sr_packet *icmp_pkt){

  struct sr_ethernet_hdr* original_ether_hdr = 0;
  struct sr_ip_hdr* original_ip_hdr = 0;
  struct sr_if* original_if_dest = 0;
  struct sr_ethernet_hdr* new_ether_hdr = 0;
  struct sr_ip_hdr* new_ip_hdr = 0;
  struct sr_icmp_t3_hdr* icmp_t3_hdr = 0;
  unsigned int pkt_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)
    + sizeof(struct sr_icmp_t3_hdr);
  uint8_t* imcp_unknown_host_pkt = malloc(pkt_len);

  /* Get original headerss */
  original_ether_hdr = (struct sr_ethernet_hdr*)icmp_pkt->buf;
  original_ip_hdr = (struct sr_ip_hdr*)(icmp_pkt->buf + sizeof(struct sr_ethernet_hdr));
  original_if_dest = sr_get_interface(sr, icmp_pkt->iface);

  new_ether_hdr = (struct sr_ethernet_hdr*)imcp_unknown_host_pkt;
  new_ip_hdr = (struct sr_ip_hdr*)(imcp_unknown_host_pkt + sizeof(struct sr_ethernet_hdr));
  icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(imcp_unknown_host_pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  /* Refactor this into its own function later */
  memcpy(new_ether_hdr->ether_dhost, original_ether_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ether_hdr->ether_shost, original_if_dest->addr, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = htons(ethertype_ip);

  memset(&(new_ip_hdr->ip_sum),0,sizeof(uint16_t));
  new_ip_hdr->ip_v = original_ip_hdr->ip_v;
  new_ip_hdr->ip_hl = original_ip_hdr->ip_hl; /* ip_hl is in words */
  new_ip_hdr->ip_tos = original_ip_hdr->ip_tos;
  new_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
  new_ip_hdr->ip_id = 0; /* Because no fragmentation */
  new_ip_hdr->ip_off = htons(IP_DF);
  new_ip_hdr->ip_ttl = 64; /* Based on FAQ */
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_src = original_if_dest->ip;
  new_ip_hdr->ip_dst = original_ip_hdr->ip_src;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(struct sr_ip_hdr));

  icmp_t3_hdr->icmp_type = 3;
  icmp_t3_hdr->icmp_code = 0;
  memcpy(icmp_t3_hdr->data, original_ip_hdr, ICMP_DATA_SIZE);
  icmp_t3_hdr->icmp_sum = 0;
  icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));

  sr_send_packet(sr, imcp_unknown_host_pkt, pkt_len, icmp_pkt->iface);

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
        new_pkt->next = req->packets;
        req->packets = new_pkt;
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
