
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#define MIN_PORT 1024
#define MAX_PORT_NUMBER 48127
#define MIN_ICMP_ID_NUMBER 256
#define MAX_ICMP_ID_NUMBER 65535


#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  unsigned int icmp_timeout;
  unsigned int icmp_query_timeout;
  unsigned int tcp_establish_timeout;
  unsigned int tcp_transit_timeout;
  /* sketchy idea for nat to point back to sr */

  /* pretty ugly way of implimentation
    basically all everytime we open a new port use used_port_marker + 1
    until its at AVALIBLE_PORTS then loop around ot beginning
      Reminder to mark port_array[x] as
      same idea with icmp_id_array
  */

  uint8_t port_array[MAX_PORT_NUMBER];
  uint16_t used_port_marker;

  uint8_t icmp_id_array[MAX_ICMP_ID_NUMBER];
  uint16_t used_icmp_id_marker;


  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, uint16_t aux_ext,
   sr_nat_mapping_type type );

#endif
