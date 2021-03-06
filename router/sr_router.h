/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "stdlib.h"
#include "sr_nat.h"


/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

typedef enum {
  pkt_outgoing,
  pkt_incoming,
  pkt_inner,
  pkt_drop
} pkt_path;

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
    /* nat */
    unsigned int mode;
    struct sr_nat nat;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void send_arp_reply (struct sr_instance* , uint8_t *, char*);
/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/* custom methods */
void router_arp_reply(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);
void addr_ip_int(uint32_t ip, char* buffer);
void handle_ip_request(struct sr_instance*, unsigned int, uint8_t*, char*);
struct sr_rt* longest_pf_match(uint32_t, struct sr_instance*);
struct sr_if* get_interface(struct sr_instance*, uint32_t);
void handle_icmp_unreachable(struct sr_instance*, unsigned int, uint8_t*, uint8_t, uint8_t);
void router_echo_icmp_request (struct sr_instance* sr, unsigned int len, uint8_t* packet);
/* --sr_nat.c --*/
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );
  struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
      uint16_t aux_ext, sr_nat_mapping_type type );

/* custom nat methods */
pkt_path get_pkt_direction(struct sr_instance* sr, uint32_t dest_ip, uint32_t src_ip);
void handle_nat_icmp_incoming(struct sr_instance* sr, unsigned int len, uint8_t * packet,
  char* interface);
void handle_nat_icmp_outgoing(struct sr_instance* sr, unsigned int len, uint8_t * packet,
  char* interface);
uint16_t generate_valid_aux_ext (struct sr_nat* sr);
void handle_nat_ip_request(struct sr_instance* sr, unsigned int len, uint8_t *
  packet/* lent */, char* interface/* lent */);
void handle_nat_icmp(struct sr_instance* sr, unsigned int len, uint8_t * packet/* lent */, char* interface, pkt_path direction);
#endif /* SR_ROUTER_H */
