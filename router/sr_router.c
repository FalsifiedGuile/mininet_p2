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
#include <inttypes.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_nat.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "stdlib.h"


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
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */


}

 /* -- sr_init -- */

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

  uint16_t pkt_type = ethertype(packet);
  if(pkt_type == ethertype_arp){
    struct sr_arp_hdr *arp_hdr = 0;
    struct sr_if * dest_interface = 0;
    dest_interface = sr_get_interface(sr, interface);
    arp_hdr = (struct sr_arp_hdr*)(sizeof(struct sr_ethernet_hdr) + packet);
    uint16_t arp_op = ntohs(arp_hdr->ar_op);
    if (arp_op == arp_op_request){
      if(dest_interface < 0){
      } else {
        router_arp_reply(sr, packet, len, interface);
      }

    } else if (arp_op == arp_op_reply){
      send_arp_reply(sr, packet, interface);

    }
  }
  if(pkt_type == ethertype_ip){
    if (sr->mode == 0){
      printf("handling non-nat packet\n");
      handle_ip_request(sr,len,packet,interface);
    } else if (sr->mode == 1){
      printf("handling nat packet\n");
      handle_nat_ip_request(sr,len,packet,interface);
    } else{
      printf("Error invalid mode variable of %d\n", sr->mode);
    }

  }
}
/* Nat function */
void handle_nat_ip_request(struct sr_instance* sr, unsigned int len, uint8_t *
  packet/* lent */, char* interface/* lent */){
  /*Check if ICMP or TCP*/
  uint8_t* p = (packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) p;

  struct sr_if* dest_interface = get_interface(sr, ip_header->ip_dst);
  printf("--where the ip packet is heading to--\n" );
  print_addr_ip_int(ntohl(ip_header->ip_dst));
  /*Packet is destined to a router interface*/
  uint8_t ip_type = ip_protocol(p);
  pkt_path direction = get_pkt_direction(sr, ip_header->ip_dst, ip_header->ip_src);
  if (direction == pkt_drop){
    printf("Pkt not for us \n");
    return;
  }
  if(ip_type == ip_protocol_icmp){
    /* handle_nat_icmp stuff */
    printf("handle nat_ip_protocol_icmp\n");
    handle_nat_icmp(sr, len, packet, interface, direction);
  } else if (ip_type == ip_protocol_tcp){
    /* handle_nat_tcp */
  } else {
    printf("Error invalid packet\n");
    /* drop packet */
    return;
  }
  /*
  If packet is outbound (internal -> external)
  	insert or lookup unique mapping
  else:
  	if no mapping and not a SYN (for simultaneous open)
  		drop packet
    Rewrite IP src (dst) for outgoing (incoming) packets
    Rewrite ICMP ID / TCP port
    Update relevant checksums
    Route packet
    */
}
/* return the direction of the packet in relation to NAT */
pkt_path get_pkt_direction(struct sr_instance* sr, uint32_t dest_ip, uint32_t src_ip){
  /* do something */
  /* check if destination ip matches NAT eth2 */
  struct sr_if *eth2 = NULL;
  int eth1 = -1;
  eth2 = sr_get_interface(sr, "eth2");
  if (dest_ip == eth2->ip){
    printf("pkt_incoming\n");
    return pkt_incoming;
  } else {
    struct sr_rt* src_entry = longest_pf_match(src_ip, sr);
    /* check if actually outgoing */
    struct sr_rt* dest_entry = longest_pf_match(dest_ip, sr);
    if (strncmp(dest_entry->interface, "eth1", 4) == 0) {
			eth1 = 0;
		}
    if (src_entry && eth1 != 0){
      printf("pkt_outgoing\n");
      printf("--dest--\n" );
      print_addr_ip_int(ntohl(dest_ip));
      printf("--src--\n" );
      print_addr_ip_int(ntohl(src_ip));
      return pkt_outgoing;
    } else if (src_entry && dest_entry){
      printf("pkt_inner\n");
      return pkt_inner;
    }
  }
  return pkt_drop;
  /* if source is in NAT aka eth1
   its pkt_outgoing*/
}

void handle_nat_icmp(struct sr_instance* sr, unsigned int len,
  uint8_t * packet/* lent */, char* interface, pkt_path direction){
    /* modify packet for nat */
    uint8_t* p = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) p;

    switch(direction){
      case pkt_incoming:
        printf("handle_nat_icmp_incoming --\n" );
        handle_nat_icmp_incoming(sr, len, packet, interface);
        break;
      case pkt_outgoing:
        printf("handle_nat_icmp_outgoing --\n" );
        print_addr_ip_int(ntohl(ip_header->ip_dst));
        handle_nat_icmp_outgoing(sr, len, packet, interface);

        break;
      default :
        break;
    }
    if (direction != pkt_inner){
      ip_header->ip_sum = 0;
      ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));
    }

    printf("handling the new ip request\n");
    print_addr_ip_int(ntohl(ip_header->ip_src));
    print_addr_ip_int(ntohl(ip_header->ip_dst));



    handle_ip_request(sr, len, packet, interface);
}

void handle_nat_icmp_incoming(struct sr_instance* sr, unsigned int len, uint8_t * packet,
  char* interface){
    uint8_t* p = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) p;
    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
    printf("sr_nat_mapping lookup --\n" );
    printf("incoming icmp id %d\n", icmp_header->icmp_id);
    print_addr_ip_int(ntohl(icmp_header->icmp_id));
    struct sr_nat_mapping *nat_lookup = sr_nat_lookup_external(&(sr->nat), icmp_header->icmp_id, nat_mapping_icmp);
    printf("modify icmp header --\n" );
    if (nat_lookup){
      if(icmp_header->icmp_type == 0)
      ip_header->ip_dst = nat_lookup->ip_int;
      icmp_header->icmp_id = nat_lookup->aux_int;
      printf("set the required things --\n" );
      icmp_header->icmp_sum = 0;
      icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
    }
    if(!nat_lookup){
        printf("didnt find anything --\n" );
    }

}

void handle_nat_icmp_outgoing(struct sr_instance* sr, unsigned int len, uint8_t * packet,
  char* interface){
    printf("original outgoing packet\n");
    print_hdr_ip(packet);
    uint8_t* p = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) p;
    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
    struct sr_nat_mapping *nat_lookup = sr_nat_lookup_internal(&(sr->nat), ip_header->ip_src,  icmp_header->icmp_id, nat_mapping_icmp);
     /*if null add insert it to NAT mapping
     if !null modify ip_src, id, and ip_sum*/
     if (!nat_lookup){
       printf("creating new nat\n");
       uint16_t aux_ext = generate_valid_aux_ext(&(sr->nat));
       if (aux_ext < 0){
         printf("ERROR no avalible ports found via generate_valid_aux_ext \n");
       }
       struct sr_if *externalIf = sr_get_interface(sr, "eth2");

       printf("real ip_dst --\n" );
       print_addr_ip_int(ntohl(ip_header->ip_dst));
       uint32_t ip_ext = externalIf->ip;
       print_addr_ip_int(ntohl(ip_ext));
       nat_lookup = sr_nat_insert_mapping(&(sr->nat), ip_header->ip_src, icmp_header->icmp_id,
        ip_ext, aux_ext, nat_mapping_icmp);
        printf("inserted %d\n", aux_ext);
     } else {
       printf("nat found!\n");
       nat_lookup->last_updated = time(NULL);
     }
     printf("ip_src original %d\n", ip_header->ip_src );
     print_addr_ip_int(ntohl(ip_header->ip_src));
     ip_header->ip_src = nat_lookup->ip_ext;
     printf("ip_src updated %d\n", ip_header->ip_src );
     print_addr_ip_int(ntohl(ip_header->ip_src));
     icmp_header->icmp_id = nat_lookup->aux_ext;
     if (icmp_header->icmp_id == 3){
       icmp_header->icmp_sum = 0;
       icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
     }
     printf("new icmp id\n" );
     print_addr_ip_int(ntohl(icmp_header->icmp_id));
    return;
}

uint16_t generate_valid_aux_ext (struct sr_nat* sr){
  /* check if current marker + 1 is within bounds and useable */
  uint16_t no_valid_icmp_avalible_chker = sr->used_icmp_id_marker;

  while(1){
    sr->used_icmp_id_marker++;
    /* check if there is no avalible ports */
    if (sr->used_icmp_id_marker == no_valid_icmp_avalible_chker){
        return -1;
    }
    if (sr->used_icmp_id_marker == MAX_ICMP_ID_NUMBER){
      sr->used_icmp_id_marker = MIN_ICMP_ID_NUMBER;
    }
    if (sr->icmp_id_array[sr->used_icmp_id_marker] == 0){
      sr->icmp_id_array[sr->used_icmp_id_marker] = 1;
      return sr->used_icmp_id_marker;
    }
  }

}
void router_arp_reply(struct sr_instance* sr,
          uint8_t * packet/* lent */,
          unsigned int len,
          char* interface/* lent */) {
  struct sr_arp_hdr* old_arp_hdr = 0;
  struct sr_if* request_interface = 0;
  struct sr_ethernet_hdr *reply_eth_hdr = 0;
  struct sr_arp_hdr *reply_arp_hdr = 0;
  old_arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  request_interface = sr_get_interface(sr, interface);

  uint8_t *reply_arp_pkt = malloc(len);
  memcpy(reply_arp_pkt, packet, len);

  reply_arp_hdr = (struct sr_arp_hdr*)(sizeof(struct sr_ethernet_hdr) + reply_arp_pkt);
  reply_eth_hdr = (struct sr_ethernet_hdr*)reply_arp_pkt;

  memcpy(reply_eth_hdr->ether_dhost, reply_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_eth_hdr->ether_shost, request_interface->addr, ETHER_ADDR_LEN);
  reply_eth_hdr->ether_type = htons(ethertype_arp);
  reply_arp_hdr->ar_sip = request_interface->ip;
  memcpy(reply_arp_hdr->ar_sha, request_interface->addr, ETHER_ADDR_LEN);
  memcpy(reply_arp_hdr->ar_tha, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = old_arp_hdr->ar_sip;
  reply_arp_hdr->ar_op = htons(arp_op_reply);

  sr_send_packet(sr, reply_arp_pkt, len, request_interface->name);
}
void send_arp_reply(struct sr_instance* sr,
          uint8_t * packet/* lent */,
          char* interface/* lent */) {
    int x = 0;
    struct sr_arp_hdr *arp_hdr = 0;
    struct sr_if * dest_interface = 0;
    struct sr_arpreq *req = 0;

    arp_hdr = (struct sr_arp_hdr*)(sizeof(struct sr_ethernet_hdr) + packet);
    dest_interface = sr_get_interface(sr, interface);

    if (dest_interface != 0){
      req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    }


    if(req != NULL) {
      struct sr_packet *arp_rep_pkt, *next = NULL;
      arp_rep_pkt = req->packets;
      while(arp_rep_pkt) {
        next = arp_rep_pkt->next;

        struct sr_ethernet_hdr *eth_hdr = 0;
        struct sr_ip_hdr *ip_hdr = 0;

        eth_hdr =(struct sr_ethernet_hdr*)arp_rep_pkt->buf;
        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, dest_interface->addr, ETHER_ADDR_LEN);

        ip_hdr = (struct sr_ip_hdr*)(sizeof(struct sr_ethernet_hdr) + arp_rep_pkt->buf);
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
        x = sr_send_packet(sr, arp_rep_pkt->buf, arp_rep_pkt->len, dest_interface->name);
        arp_rep_pkt = next;
      }
      if (x >= 0){
        sr_arpreq_destroy(&sr->cache, req);
      }

    } else {
      printf("didnt find it in cache\n");
    }

}

/* modified version of print_addr_ip_int in sr_utils.c */
void addr_ip_str(uint32_t ip, char* buffer) {
  sprintf(
    buffer, "%d.%d.%d.%d", ip >> 24, (ip << 8) >> 24, (ip << 16) >> 24, (ip << 24) >> 24);
}


void handle_ip_request(struct sr_instance* sr, unsigned int len, uint8_t * packet/* lent */, char* interface/* lent */){
        printf("IP packet recieved.\n");
        /*Construct payload and ip hdr*/
        uint8_t* p = (packet + sizeof(sr_ethernet_hdr_t));
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) p;

        struct sr_if* dest_interface = get_interface(sr, ip_header->ip_dst);
        /*Packet is destined to a router interface*/

        if(dest_interface){
          printf("is router interface\n");
          uint8_t ip_type = ip_protocol(p);
          printf("ip type %d \n", ip_type);
          if(ip_type == ip_protocol_icmp){
            printf("ICMP Request.\n");
            sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
            if(icmp_header->icmp_type == 8){
            /*Send echo reply*/
            router_echo_icmp_request (sr, len, packet);
            }

          }
          else{
            printf("Packet is a TCP/UDP.\n");
			      handle_icmp_unreachable(sr,len,packet,3,3);
          }
        }
        else{
          /*Packet destination ip is not a router interface*/
          /*Construct IP header*/
          sr_ip_hdr_t* ip_header2 = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
          ip_header2->ip_ttl--; /*Decrement ttl*/
          if(ip_header2->ip_ttl == 0){
          /*Time exceeded message*/
            handle_icmp_unreachable(sr,len,packet,0,11);
            return;
          }

          ip_header2->ip_sum=0;
          ip_header2->ip_sum=cksum(ip_header2,sizeof(struct sr_ip_hdr));

          /*Find routing table entry using longest pf match function*/

          struct sr_rt* dest_entry = longest_pf_match(ip_header2->ip_dst,sr);
          if (dest_entry){
          /*find destination interface*/
          struct sr_if* dest_interface = sr_get_interface(sr, dest_entry->interface);
          if(dest_interface){
            struct sr_arpentry* cached_val = sr_arpcache_lookup(&sr->cache,dest_entry->gw.s_addr);
            if(cached_val){
            /*send packet forward*/
            sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
            memcpy(ethernet_header->ether_dhost, cached_val->mac, ETHER_ADDR_LEN);
            memcpy(ethernet_header->ether_shost, dest_interface->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr,packet,len,dest_interface->name);
            free(cached_val);
            } else{
            /*queue arp request.*/
			  printf("Queuing arp request.\n");
              sr_arpcache_queuereq(&sr->cache,dest_entry->gw.s_addr,packet,len,dest_interface->name);
            }
          }
          else{
          sr_arpcache_queuereq(&sr->cache,dest_entry->gw.s_addr,packet,len,dest_interface->name);
          printf("Requested interface not found.\n");
          return;
          }
          }
          else{
            /*Entry does not exist in routing table*/
            printf("entry not in routing table.\n");
            handle_icmp_unreachable(sr,len,packet,0,3);
            return;
          }
        }
}

void handle_icmp_unreachable(struct sr_instance* sr, unsigned int len, uint8_t* packet, uint8_t code, uint8_t type){
/*Construct IP headers, find routing table entry and destination interface to handle packet*/
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt* sourceLMP = longest_pf_match(ip_header->ip_src,sr);
  if(sourceLMP){
    struct sr_if* dest_interface = sr_get_interface(sr,sourceLMP->interface);
    /*construction of new icmp packet to send*/
    unsigned int packet_len = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
    uint8_t* packet_to_send = malloc(packet_len);
    assert(packet_to_send);

    /*construct new ethernet,ip,icmp headers*/
    sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(packet_to_send +  sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t* new_ethernet_header = (sr_ethernet_hdr_t*)packet_to_send;
    sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*)(packet_to_send + sizeof(sr_ethernet_hdr_t) + (ip_header->ip_hl * 4));

    /*Set new ethernet headers source and mac*/
    memset(new_ethernet_header->ether_dhost, 0, ETHER_ADDR_LEN);
    memset(new_ethernet_header->ether_shost, 0, ETHER_ADDR_LEN);

    new_ethernet_header->ether_type= htons(ethertype_ip);


    /*set ip header values*/
    new_ip_header->ip_src = code == 3 ? ip_header->ip_dst : dest_interface->ip;
    new_ip_header->ip_dst = ip_header->ip_src;


    new_ip_header->ip_v = 4;
    new_ip_header->ip_tos = 0;
    new_ip_header->ip_p = ip_protocol_icmp;
    new_ip_header->ip_hl = sizeof(sr_ip_hdr_t)/4;
    new_ip_header->ip_id = htons(0);
    new_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_header->ip_off = htons(IP_DF);
    new_ip_header->ip_ttl = 64;

    new_ip_header->ip_sum = 0;
    new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));

    /*set icmp header values*/
    icmp_header->icmp_type = type;
    icmp_header->icmp_code = code;
    icmp_header->unused = 0;
    icmp_header->next_mtu = 0;
    memcpy(icmp_header->data, ip_header, ICMP_DATA_SIZE);

    /*Checksums for icmp header*/
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
    if(dest_interface){
      struct sr_arpentry* cached_val = sr_arpcache_lookup(&sr->cache,sourceLMP->gw.s_addr);
      if(cached_val){
      /*send packet forward*/
        sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet_to_send;
        memcpy(ethernet_header->ether_dhost, cached_val->mac, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, dest_interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr,packet_to_send,packet_len,dest_interface->name);
        free(cached_val);
      } else{
      /*queue arp request.*/
        printf("Queuing arp request.\n");
        sr_arpcache_queuereq(&sr->cache,sourceLMP->gw.s_addr,packet_to_send,packet_len,dest_interface->name);
        }
    }

  }
  else{
  printf("No routing table entry found for source IP specified.\n");
  return;
  }

}


void router_echo_icmp_request (struct sr_instance* sr, unsigned int len, uint8_t* packet){
  printf("Sending router_echo_icmp_request\n");
  struct sr_if* request_interface = 0;
  struct sr_rt* request_if_route = 0;
  struct sr_ip_hdr* old_ip_hdr = 0;
  struct sr_ethernet_hdr *old_eth_hdr = 0;

  struct sr_ip_hdr* reply_ip_hdr = 0;
  struct sr_ethernet_hdr *reply_eth_hdr = 0;
  struct sr_icmp_hdr *reply_icmp_hdr = 0;

  uint8_t *icmp_packet = malloc(len);
  memcpy(icmp_packet, packet, len);

  old_eth_hdr = (struct sr_ethernet_hdr*)packet;
  old_ip_hdr = (struct sr_ip_hdr*)(sizeof(struct sr_ethernet_hdr) + packet);

  reply_eth_hdr = (struct sr_ethernet_hdr*)icmp_packet;
  reply_ip_hdr = (struct sr_ip_hdr*)(sizeof(struct sr_ethernet_hdr) + icmp_packet);
  reply_icmp_hdr = (struct sr_icmp_hdr*)(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + icmp_packet);
  request_if_route = longest_pf_match(old_ip_hdr->ip_src, sr);
  request_interface = sr_get_interface(sr, request_if_route->interface);

  memcpy(reply_eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_eth_hdr->ether_shost, request_interface->addr, ETHER_ADDR_LEN);

  reply_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  reply_ip_hdr->ip_src = old_ip_hdr->ip_dst;
  reply_ip_hdr->ip_ttl = 64; /* Based on FAQ */
  reply_ip_hdr->ip_p = ip_protocol_icmp;
  memset(&(reply_ip_hdr->ip_sum), 0, sizeof(uint16_t));
  reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));

  reply_icmp_hdr->icmp_type = 0;
  memset(&(reply_icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
  reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  sr_arpcache_queuereq(&sr->cache,reply_ip_hdr->ip_dst, icmp_packet,len,request_interface->name);
  sr_send_packet(sr, icmp_packet, len, request_interface->name);
}

struct sr_rt* longest_pf_match(uint32_t destIP, struct sr_instance* sr){
  struct sr_rt* pf_val = NULL;
  char ip_val[15];
  addr_ip_str(ntohl(destIP), ip_val);

  struct sr_rt* routing_table_entry = sr -> routing_table;
  while(routing_table_entry){
  /* find longest prefix match and update pf_val if needed */
    if ((routing_table_entry->dest.s_addr & routing_table_entry->mask.s_addr) == (destIP & routing_table_entry->mask.s_addr)){
      if (!pf_val || routing_table_entry->mask.s_addr > pf_val->mask.s_addr){
        pf_val = routing_table_entry;
      }
    }
    routing_table_entry = routing_table_entry->next;
  }

  if(pf_val){
  char dest_IP_val[15];
  addr_ip_str(ntohl(pf_val->dest.s_addr),dest_IP_val);
  char gw_val[15];
  addr_ip_str(ntohl(pf_val->gw.s_addr),gw_val);
  char mask_val[15];
  addr_ip_str(ntohl(pf_val->mask.s_addr),mask_val);
  }
  else{
  printf("No matches found via lmp.");
  }

  return pf_val;
}
/*this function returns an interface based on the ip provided, similar to get_inferface in sr_if */
struct sr_if* get_interface(struct sr_instance* sr, uint32_t destIP){
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(destIP);
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
       if(if_walker->ip == destIP)
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
}
  /*sr_add_interface(sr, interface);
  sr_set_ether_ip(struct sr_instance* , uint32_t );
  sr_set_ether_addr(struct sr_instance* , const unsigned char* );
  sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
  */

  /* fill in code here */

/* end sr_ForwardPacket */
