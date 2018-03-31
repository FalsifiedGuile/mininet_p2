
#include <signal.h>
#include <assert.h>
#include <unistd.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_nat.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *current = nat->mappings;

  while (current != NULL) {
    if (current->aux_ext == aux_ext && current->type == type) {
      /* Found mapping */
      current->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, current, sizeof(struct sr_nat_mapping));
      break;
    }
    current = current->next;
  }


  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
	struct sr_nat_mapping *current = nat->mappings;

	while (current != NULL) {
		if (current->ip_int == ip_int && current->aux_int == aux_int && current->type == type) {
			/* Found mapping */
			current->last_updated = time(NULL);
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, current, sizeof(struct sr_nat_mapping));
			break;
		}
		current = current->next;
	}

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, uint16_t aux_ext,
   sr_nat_mapping_type type) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *mapping_copy = NULL;
  struct sr_rt *lpm = NULL;
  time_t curtime = time(NULL);

  mapping = malloc(sizeof(struct sr_nat_mapping));

  /* set internal */
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->last_updated = curtime;
  mapping->conns = NULL; /* obviously due to no conns set*/

  /* set external */
  mapping->ip_ext = ip_ext;
  mapping->aux_ext = aux_ext;

  mapping_copy = malloc(sizeof(struct sr_nat_mapping));
	memcpy(mapping_copy, mapping, sizeof(struct sr_nat_mapping));


  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
