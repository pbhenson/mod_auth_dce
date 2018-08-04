/*
 * DCE Authentication Module for Apache HTTP Server
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1996-2000 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef MOD_AUTH_DCE_H
#define MOD_AUTH_DCE_H

/* #define DEBUG */

#ifdef __GNUC__ 
#ifdef DEBUG
#define DEBUG_R(X...) ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r, X)
#define DEBUG_S(X...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s, X)
#else
#define DEBUG_R(X...)
#define DEBUG_S(X...)
#endif
#else
#define DEBUG_R()
#define DEBUG_S()
#endif

/* Comment out on systems without DFS */
#define WITH_DFS

#ifndef NO_CACHING
/* How often per server process to log cache statistics, comment out to disable */
#define CACHE_STATS_INTERVAL 500

/* How many extra random characters to append to a given username for cache stress testing */
/* #define CACHE_TEST_LEVEL 4 */
#endif

typedef struct server_config_struct {
    char *user;
    char *keytab;
    int certify_identity;
#ifndef NO_CACHING
    unsigned int cache_buckets;
    unsigned int cache_graceperiod;
    unsigned int cache_lifetime;
    unsigned int cache_max_idle;
    unsigned int cache_sweep_interval;
#endif
} server_config_rec;

typedef struct dir_config_struct {
  int active;
#ifdef WITH_DFS
  int dfs_authorization;
#endif
  int include_pw;
  int impersonate_browser;
  int authoritative;
  char *index_names;
} dir_config_rec;


typedef struct request_config_struct {
#ifndef NO_CACHING
  unsigned char hash_key[16];
  unsigned int hash_index;
  unsigned long pag;
#else
  void *login_context;
#endif
} request_config_rec;

#ifndef NO_CACHING
void auth_dce_purge_context(server_rec *s, unsigned long pag);
void auth_dce_initialize_cache(server_rec *s, pool *p);
void auth_dce_find_cached_context(request_rec *r, request_config_rec *request_config, char *username, char *password);
void auth_dce_add_cached_context(request_rec *r, request_config_rec *request_config);
void auth_dce_release_cached_context(request_rec *r, request_config_rec *request_config);
#endif

#endif

