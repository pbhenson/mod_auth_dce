/*
 * DCE Authentication Module for Apache HTTP Server
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1996-2000 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NO_CACHING

/* Native Solaris pthreads */
#include <pthread.h>

#include <sys/mman.h>
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#include "ap_md5.h"
#include "mod_auth_dce.h"

#define SLOTS_PER_BUCKET 4

typedef struct cache_entry {
  unsigned char key[16];
  unsigned long pag;
  unsigned int refcount;
  time_t last_use;
  time_t expiration;
} cache_entry_rec;

typedef struct hash_table_entry {
  pthread_mutex_t mutex;
  cache_entry_rec entries[SLOTS_PER_BUCKET];
} hash_table_entry_rec;

static hash_table_entry_rec *hash_table;
static pthread_t cache_thread;

extern server_config_rec auth_dce_server_config;

static void pthread_delay_np(struct timespec *sleep_interval)
{
  pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  struct timespec wakeup_time = *sleep_interval;
  
  pthread_mutex_lock(&mutex);
  wakeup_time.tv_sec += time(NULL);
  pthread_cond_timedwait(&cond, &mutex, &wakeup_time);
}


static void cache_cleanup(void *arg)
{
  int bucket_index;
  int slot_index;
  server_rec *s = (server_rec *)arg;

  DEBUG_S("auth_dce.cache_cleanup: cancelling cache cleanup thread");
  
  pthread_cancel(cache_thread);

  DEBUG_S("auth_dce.cache_cleanup: cleaning cache data structure");
  
  for (bucket_index = 0; bucket_index < auth_dce_server_config.cache_buckets; bucket_index++)
    {
      pthread_mutex_destroy(&hash_table[bucket_index].mutex);
      for (slot_index = 0; slot_index < SLOTS_PER_BUCKET; slot_index++)
	{
	  if (hash_table[bucket_index].entries[slot_index].pag != 0)
	    auth_dce_purge_context(s, hash_table[bucket_index].entries[slot_index].pag);
	}
    }

  DEBUG_S("auth_dce.cache_cleanup: releasing shared memory");
  
  munmap((void *)hash_table, sizeof(hash_table_entry_rec) * auth_dce_server_config.cache_buckets);
}


static void cache_maintain(void *arg)
{
  int bucket_index;
  int slot_index;
  time_t now;
  struct timespec sweep_interval;
  struct timespec sleep_interval;
  int tries;
  unsigned int pag_queue[SLOTS_PER_BUCKET];
  int pag_index = 0;
  server_rec *s = (server_rec *)arg;

  sweep_interval.tv_sec = auth_dce_server_config.cache_sweep_interval;
  sweep_interval.tv_nsec = 0;

  sleep_interval.tv_sec = 0;
  sleep_interval.tv_nsec = 100000000; /* 1/10 second */

  DEBUG_S("auth_dce.cache_maintain: entering cache maintenance loop");
  
  while (1)
    {
#ifdef CACHE_STATS_INTERVAL
      int contexts_reviewed = 0;
      int contexts_deleted = 0;
      int full_buckets = 0;
#endif

      pthread_delay_np(&sweep_interval);

      DEBUG_S("auth_dce.cache_maintain: performing cache sweep");

      now = time(NULL);
      
      for (bucket_index = 0; bucket_index < auth_dce_server_config.cache_buckets; bucket_index++)
	{
#ifdef CACHE_STATS_INTERVAL
	  int full_slots = 0;
#endif
	  tries = 0;
      
	  while (1)
	    {
	      if (!pthread_mutex_trylock(&hash_table[bucket_index].mutex))
		{
		  for (slot_index = 0; slot_index < SLOTS_PER_BUCKET; slot_index++)
		    {
		      if (hash_table[bucket_index].entries[slot_index].pag != 0)
			{
#ifdef CACHE_STATS_INTERVAL
			  contexts_reviewed++;
			  full_slots++;
#endif
			  if (((hash_table[bucket_index].entries[slot_index].expiration < now) ||
			       (hash_table[bucket_index].entries[slot_index].last_use + auth_dce_server_config.cache_max_idle < now)) &&
			      ((hash_table[bucket_index].entries[slot_index].refcount == 0) ||
			       (hash_table[bucket_index].entries[slot_index].expiration + auth_dce_server_config.cache_graceperiod < now)))
			    {
#ifdef CACHE_STATS_INTERVAL
			      contexts_deleted++;
#endif
			      pag_queue[pag_index++] = hash_table[bucket_index].entries[slot_index].pag;
			      hash_table[bucket_index].entries[slot_index].pag = 0;
			    }
			}
		    }
		  
		  pthread_mutex_unlock(&hash_table[bucket_index].mutex);
#ifdef CACHE_STATS_INTERVAL
		  if (full_slots == SLOTS_PER_BUCKET) full_buckets++;
#endif
		  
		  while (pag_index > 0)
		    auth_dce_purge_context(s, pag_queue[--pag_index]);
		  
		  break;
		}
	      else
		{
		  if (++tries == 5)
		    {
		      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
				   "auth_dce.cache_maintain: %d failures locking mutex for bucket %d, skipping", tries, bucket_index);
		      break;
		    }

		  DEBUG_S("auth_dce.cache_maintain: failed to lock mutex for bucket %d", bucket_index);
		  pthread_delay_np(&sleep_interval);
		}
	    }
	}
#ifdef CACHE_STATS_INTERVAL
      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s,
		   "auth_dce.cache_maintain: reviewed %d contexts, deleted %d, %d buckets full", contexts_reviewed, contexts_deleted, full_buckets);
#endif
    }

}


void auth_dce_initialize_cache(server_rec *s, pool *p) {

  pthread_mutexattr_t mutex_attr;
  int fd;
  int bucket_index;

  DEBUG_S("auth_dce.initialize_cache: initializing shared memory for cache");
  
  if ((fd = open("/dev/zero", O_RDWR)) == -1)
    {
      ap_log_error(APLOG_MARK, APLOG_EMERG, s,
		   "auth_dce.initialize_cache: failed to open /dev/zero");
      exit(1);
    }
  
  hash_table = (hash_table_entry_rec *) mmap((caddr_t) 0, sizeof(hash_table_entry_rec) * auth_dce_server_config.cache_buckets,
					  PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  
  if (hash_table == (void *) (caddr_t) - 1)
    {
      ap_log_error(APLOG_MARK, APLOG_EMERG, s,
		   "auth_dce.initialize_cache: mmap failed");
      exit(1);
    }
  
  close(fd);

  memset(hash_table, 0, sizeof(hash_table_entry_rec) * auth_dce_server_config.cache_buckets);
  
  if ((errno = pthread_mutexattr_init(&mutex_attr)))
    {
      ap_log_error(APLOG_MARK, APLOG_EMERG, s,
		   "auth_dce.initialize_cache: pthread_mutexattr_init failed");
      exit(1);
    }
  
  if ((errno = pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED)))
    {
      ap_log_error(APLOG_MARK, APLOG_EMERG, s,
		   "auth_dce.initialize_cache: pthread_mutexattr_setpshared failed");
      exit(1);
    }

  for (bucket_index = 0; bucket_index < auth_dce_server_config.cache_buckets; bucket_index++)
    if ((errno = pthread_mutex_init(&hash_table[bucket_index].mutex, &mutex_attr)))
      {
	ap_log_error(APLOG_MARK, APLOG_EMERG, s,
		     "auth_dce.initialize_cache: pthread_mutex_init failed");
	exit(1);
      }
  
  if (pthread_create(&cache_thread, NULL, (void *)cache_maintain, (void *)s))
    {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
		   "auth_dce.initialize_cache: cache maintenance pthread create failed");
      exit(1);
    }

  DEBUG_S("auth_dce.initialize_cache: registering cache cleanup");
  ap_register_cleanup(p, NULL, cache_cleanup, ap_null_cleanup);
}


void auth_dce_find_cached_context(request_rec *r, request_config_rec *request_config, char *username, char *password) {

  AP_MD5_CTX md5_context;
  time_t now = time(NULL);
  struct timespec sleep_interval;
  int tries = 0;
  int slot_index;

#ifdef CACHE_STATS_INTERVAL
  static unsigned int cache_accesses = 0;
  static unsigned int cache_hits = 0;
  static unsigned int total_cache_accesses = 0;
  static unsigned int total_cache_hits = 0;
#endif
  
#ifdef CACHE_TEST_LEVEL
  int username_len = strlen(username);
  int index;
  char *testname = ap_palloc(r->pool, username_len + CACHE_TEST_LEVEL + 1);

  strcpy(testname, username);

  for (index = username_len; index < username_len + CACHE_TEST_LEVEL; index++)
    testname[index] = 'A' + (lrand48() % 10);

  testname[index] = '\0';

#define username testname
#endif

#ifdef CACHE_STATS_INTERVAL
  if (cache_accesses == CACHE_STATS_INTERVAL) {
    total_cache_accesses += cache_accesses;
    total_cache_hits += cache_hits;

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
		  "auth_dce.find_cached_context: %d hits / %d accesses (%0.2f%%), %d hits / %d accesses total (%0.2f%%)",
		  cache_hits, cache_accesses, (float)cache_hits/(float)cache_accesses,
		  total_cache_hits, total_cache_accesses, (float)total_cache_hits/(float)total_cache_accesses);

    cache_hits = cache_accesses = 0;
  }
  cache_accesses++;
#endif
  
  DEBUG_R("auth_dce.find_cached_context: looking for username %s", username);
  
  ap_MD5Init(&md5_context);
  ap_MD5Update(&md5_context, (const unsigned char *)username, strlen(username));
  ap_MD5Update(&md5_context, (const unsigned char *)password, strlen(password));
  ap_MD5Final(request_config->hash_key, &md5_context);

  memcpy(&request_config->hash_index, request_config->hash_key, sizeof(request_config->hash_index));
  request_config->hash_index %= auth_dce_server_config.cache_buckets;

  DEBUG_R("auth_dce.find_cached_context: hash index set to %d", request_config->hash_index);
  
  sleep_interval.tv_sec = 0;
  sleep_interval.tv_nsec = 100000000; /* 1/10 second */

  while (1)
    {
      if (!pthread_mutex_trylock(&hash_table[request_config->hash_index].mutex))
	{
	  for (slot_index = 0; slot_index < SLOTS_PER_BUCKET; slot_index++)
	    {
	      if (memcmp(hash_table[request_config->hash_index].entries[slot_index].key, request_config->hash_key, 16) == 0)
		{
		  DEBUG_R("auth_dce.find_cached_context: found candidate context in slot %d", slot_index);
		  
		  if (hash_table[request_config->hash_index].entries[slot_index].expiration > now)
		    {
		      request_config->pag = hash_table[request_config->hash_index].entries[slot_index].pag;
		      hash_table[request_config->hash_index].entries[slot_index].refcount++;
		      hash_table[request_config->hash_index].entries[slot_index].last_use = now;

		      pthread_mutex_unlock(&hash_table[request_config->hash_index].mutex);
		      
		      DEBUG_R("auth_dce.find_cached_context: candidate context acceptable, using pag %08x", request_config->pag);

#ifdef CACHE_STATS_INTERVAL
		      cache_hits++;
#endif
		      
		      return;
		    }
		}
	    }
	  
	  pthread_mutex_unlock(&hash_table[request_config->hash_index].mutex);

	  DEBUG_R("auth_dce.find_cached_context: no acceptable contexts found for username %s", username);
	  
	  return;
	}
      
      if (++tries == 5)
	{
	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.find_cached_context: %d failures locking bucket %d, giving up", tries, request_config->hash_index);
	  
	  break;
	}

      DEBUG_R("auth_dce.find_cached_context: failed to lock mutex for bucket %d", request_config->hash_index);
      
      pthread_delay_np(&sleep_interval);
    }
}

void auth_dce_add_cached_context(request_rec *r, request_config_rec *request_config) {
  time_t now = time(NULL);
  int slot_index;
  struct timespec sleep_interval;
  int tries = 0;

  sleep_interval.tv_sec = 0;
  sleep_interval.tv_nsec = 100000000; /* 1/10 second */
    
  DEBUG_R("auth_dce.add_cached_context: attempting to add context for pag %08x", request_config->pag);
  
  while (1)
    {
      if (!pthread_mutex_trylock(&hash_table[request_config->hash_index].mutex))
	{
	  DEBUG_R("auth_dce.add_cached_context: looking for empty slot in bucket %d", request_config->hash_index);
	  
	  for (slot_index = 0; slot_index < SLOTS_PER_BUCKET; slot_index++)
	    {
	      if (hash_table[request_config->hash_index].entries[slot_index].pag == 0)
		{		  
		  memcpy(hash_table[request_config->hash_index].entries[slot_index].key, request_config->hash_key, 16);
		  hash_table[request_config->hash_index].entries[slot_index].pag = request_config->pag;
		  hash_table[request_config->hash_index].entries[slot_index].refcount = 1;
		  hash_table[request_config->hash_index].entries[slot_index].last_use = now;
		  hash_table[request_config->hash_index].entries[slot_index].expiration = now + auth_dce_server_config.cache_lifetime;

		  pthread_mutex_unlock(&hash_table[request_config->hash_index].mutex);

		  DEBUG_R("auth_dce.add_cached_context: successfully stored context in slot %d", slot_index);
		  
		  return;
		}
	    }

	  pthread_mutex_unlock(&hash_table[request_config->hash_index].mutex);

	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
			"auth_dce.add_cached_context: no empty slots found in bucket %d, marking context for purging", request_config->hash_index);
	  
	  memset(request_config->hash_key, 0, 16);
	  return;
	}

      if (++tries == 5)
	{
	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.add_cached_context: %d failures locking bucket %d, giving up", tries, request_config->hash_index);
	  
	  break;
	}

      DEBUG_R("auth_dce.add_cached_context: failed to lock mutex for bucket %d", request_config->hash_index);

      pthread_delay_np(&sleep_interval);
    }

  DEBUG_R("auth_dce.add_cached_context: failed to add context, marking for purging");
  
  memset(request_config->hash_key, 0, 16);
}

void auth_dce_release_cached_context(request_rec *r, request_config_rec *request_config) {
  int slot_index;
  struct timespec sleep_interval;
  int tries = 0;

  sleep_interval.tv_sec = 0;
  sleep_interval.tv_nsec = 100000000; /* 1/10 second */

  DEBUG_R("auth_dce.release_cached_context: trying to release pag %08x", request_config->pag);

  while (1)
    {
      if (!pthread_mutex_trylock(&hash_table[request_config->hash_index].mutex))
	{
	  DEBUG_R("auth_dce.release_cached_context: looking for pag %08x in bucket %d", request_config->pag, request_config->hash_index);
	  
	  for (slot_index = 0; slot_index < SLOTS_PER_BUCKET; slot_index++)
	    {
	      if ((memcmp(hash_table[request_config->hash_index].entries[slot_index].key, request_config->hash_key, 16) == 0) &&
		  (hash_table[request_config->hash_index].entries[slot_index].pag == request_config->pag))		
		{
		  hash_table[request_config->hash_index].entries[slot_index].refcount--;

		  pthread_mutex_unlock(&hash_table[request_config->hash_index].mutex);

		  DEBUG_R("auth_dce.release_cached_context: successfully released context for %08x", request_config->pag);
		  
		  return;
		}
	    }

	  pthread_mutex_unlock(&hash_table[request_config->hash_index].mutex);

	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
			"auth_dce.release_cached_context: context for pag %08x not found in bucket %d", request_config->pag, request_config->hash_index);
	  
	  return;
	}

      if (++tries == 5)
	{
	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.release_cached_context: %d failures locking bucket %d, giving up", tries, request_config->hash_index);
	  
	  break;
	}
      
      DEBUG_R("auth_dce.release_cached_context: failed to lock mutex for bucket %d", request_config->hash_index);
		  
      pthread_delay_np(&sleep_interval);
    }

  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
		"auth_dce.release_cached_context: possible bad reference count for pag %08x in bucket %d", request_config->pag, request_config->hash_index);
}

#else
int auth_dce_dummy() {}
#endif 
