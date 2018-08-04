/*
 * DCE Authentication Module for Apache HTTP Server
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1996,1997 Paul Henson -- see COPYRIGHT file for details
 *
 */

/* Include file to access DCE error text */
#include <dce/dce_error.h>

/* Include file to access DCE security API */
#include <dce/sec_login.h>

/* Include files to access Apache module API */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "md5.h"

/* Comment out to disable login context caching */
#define CACHING

/* Parameters and prototypes for cache when enabled */
#ifdef CACHING

/* System call to reset the DFS PAG */
#define AFSCALL_RESETPAG 20

/* How many entries to cache */
#define CACHE_SIZE 100

/* How long to keep an entry in the cache (in seconds, default 12 hours) */
#define CACHE_TTL (60*60*12)

/* How big should the login_context buffer be for export_context */
#define CACHE_BUFSIZE 128

/* Comment out following two defines to disable cache statistic generation */
#define CACHE_STATS
/* How often to output statistics */
#define CACHE_STAT_INTERVAL 500

/* Prototypes for cache interface */
static int find_cached_context(request_rec *r, sec_login_handle_t *, char *, char *);
static void add_cached_context(request_rec *r, sec_login_handle_t *, char *, char *);
#endif

/* We're still debugging... */
#define DEBUG 0

/* Production mode */
/* #undef DEBUG */


/* Define debugging log code */
#ifdef DEBUG
#define DEBUG_INFO 1
#define DEBUG_ERROR 0
#define DEBUG_CACHE 0
#define log_debug(L, X, Y) if (L <= DEBUG) log_error(X, Y)
#else
#define log_debug(L, X, Y)
#endif



/* Define module structure for per-directory configuration.
 * The structure has only one member, which determines whether DCE
 * authentication is turned on in a given directory.
 */
typedef struct auth_dce_config_struct {
  int do_auth_dce;
  char *index_names;
} auth_dce_config_rec;


/* Function to create and return an empty per-directory module
 * configuration structure.
 */
void *create_auth_dce_dir_config(pool *p, char *d)
{
    return pcalloc (p, sizeof(auth_dce_config_rec));
}


/* Function that is called to configure a directory when an AuthDCE
 * configuration directive is found.
 * It is passed a flag indicating whether DCE authentication should
 * be enabled in this directory.
 */
char *set_auth_dce(cmd_parms *cmd, void *dv, int arg)
{
  auth_dce_config_rec *d = (auth_dce_config_rec *)dv;
  
  d->do_auth_dce = arg;
  
  return NULL;
}

void *merge_dce_dir_configs(pool *p, void *basev, void *addv)
{
  auth_dce_config_rec *new=(auth_dce_config_rec*)pcalloc (p, sizeof(auth_dce_config_rec));
  auth_dce_config_rec *base = (auth_dce_config_rec *)basev;
  auth_dce_config_rec *add = (auth_dce_config_rec *)addv;

  new->do_auth_dce = add->do_auth_dce;
  new->index_names = (add->index_names) ? (add->index_names) : (base->index_names);
  
  return new;
}


/* This structure defines the configuration commands this module
 * is willing to handle.
 */
command_rec auth_dce_cmds[] = {
{ "AuthDCE", set_auth_dce, NULL, OR_AUTHCFG, FLAG,
  "Perform DCE authentication in this directory?" },
{ "DCEDirectoryIndex", set_string_slot,
    (void*)XtOffsetOf(auth_dce_config_rec, index_names),
    OR_INDEXES, RAW_ARGS, NULL },
{ NULL }
};


/* Declaration for the module configuration variable. The variable
 * is defined at this end of the module source code file.
 */
module auth_dce_module;


/* Function to verify DCE username/password and obtain network credentials
 */
int authenticate_dce_user (request_rec *r)
{
  /* Store password sent by the user */
  char *sent_pw;

  /* Store DCE login context */
  sec_login_handle_t login_context;

  /* DCE functions return status in this variable */
  error_status_t dce_st;

  /* String to store text for a given error code */
  dce_error_string_t dce_error;

  /* Variable to check the status of the error-code-to-text call */
  int dce_error_st;
     
  /* What type of credentials were obtained */
  sec_login_auth_src_t auth_src;

  /* Structure passed to DCE to verify user's password */
  sec_passwd_rec_t pw_entry;

  /* String type to pass pasword to DCE */
  sec_passwd_str_t dce_pw;

  /* Whether or not the password has expired */
  boolean32 reset_passwd;

  
  /* Obtain the per-directory configuration for this request */
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    get_module_config (r->per_dir_config, &auth_dce_module);

  log_debug(DEBUG_INFO, pstrcat(r->pool, "authenticate_dce_user: called for URI ",
                       r->uri, NULL), r->server);

  log_debug(DEBUG_INFO, pstrcat(r->pool, "authenticate_dce_user: called for filename ",
                       r->filename, NULL), r->server);


  /* Is DCE authentication turned on for this request? If not, decline it */
  if (!a->do_auth_dce)
    {
      log_debug(DEBUG_INFO, "authenticate_dce_user: do_auth_dce not set, returning DECLINED", r->server);
      return DECLINED;
    }

  
  /* If check_dce_access() didn't set the request_config variable, we don't
   * need credentials to complete the request. Return OK without bothering
   * with DCE calls
   */
  if (!get_module_config(r->request_config, &auth_dce_module))
    {
      log_debug(DEBUG_INFO, "authenticate_dce_user: request_config not set, returning OK", r->server);
      return OK;
    }

  
  /* dce_log_transaction() checks the request_config variable when it tries
   * to purge or release the DCE context. Set it to NULL initially.
   */
  set_module_config(r->request_config, &auth_dce_module, NULL);

  
  /* Call Apache function to extract the username and password information
   * from the request.
   */
  get_basic_auth_pw (r, &sent_pw);

  log_debug(DEBUG_INFO, pstrcat(r->pool, "authenticate_dce_user: request made by user ",
                       r->connection->user, NULL), r->server);

  /*  log_debug(DEBUG_INFO, pstrcat(r->pool, "authenticate_dce_user: password is  ",
                       sent_pw, NULL), r->server);
                       */


#ifdef CACHING
  if (!find_cached_context(r, &login_context, r->connection->user, sent_pw))
    {
#endif
      log_debug(DEBUG_INFO, "authenticate_dce_user: calling sec_login_setup_identity", r->server);
  
      /* sec_login_setup_identity() verifies that the username given is
       * correct and does the initial setup of the login context.
       */
      if (!sec_login_setup_identity(r->connection->user, sec_login_no_flags,
                                    &login_context, &dce_st))
        {
          /* Invalid username. Clean up and return */
          dce_error_inq_text(dce_st, dce_error, &dce_error_st);
          log_debug(DEBUG_ERROR, pstrcat(r->pool,
                               "authenticate_dce_user: sec_login_setup_identity failed for ", r->connection->user, " - ",
                               dce_error,
                               NULL),
                    r->server);
      
          sec_login_purge_context(&login_context, &dce_st);
          note_basic_auth_failure(r);
      
          log_debug(DEBUG_INFO, "authenticate_dce_user: returning AUTH_REQUIRED",
                    r->server);
          return AUTH_REQUIRED;
        }

      /* Now that the username has been verified, set up the structure
       * to validate the password.
       */
      pw_entry.version_number = sec_passwd_c_version_none;
      pw_entry.pepper = NULL;
      pw_entry.key.key_type = sec_passwd_plain;
          
      strncpy( (char *)dce_pw, sent_pw, sec_passwd_str_max_len);
      dce_pw[sec_passwd_str_max_len] = ' ';
      pw_entry.key.tagged_union.plain = &(dce_pw[0]);

      log_debug(DEBUG_INFO, "authenticate_dce_user: calling sec_login_validate_identity",
                r->server);

          
      /* sec_login_validate_identity() verifies that the correct password has
       * been furnished and completes the setup of the login context. It also
       * returns whether the user's password has expired, and what source
       * supplied the authorization.
       */
      if (!sec_login_validate_identity(login_context, &pw_entry, &reset_passwd,
                                       &auth_src, &dce_st))
        {
          /* Wrong password. Clean up and return */
          dce_error_inq_text(dce_st, dce_error, &dce_error_st);
          log_debug(DEBUG_ERROR, pstrcat(r->pool,
                               "authenticate_dce_user: sec_login_validate_ident failed for ", r->connection->user, " - ",
                               dce_error,
                               NULL),
                    r->server);
          sec_login_purge_context(&login_context, &dce_st);
          note_basic_auth_failure(r);
          log_debug(DEBUG_INFO, "authenticate_dce_user: returning AUTH_REQUIRED",
                    r->server);
          return AUTH_REQUIRED;
        }
        
      log_debug(DEBUG_INFO, "authenticate_dce_user: calling sec_login_certify_identity", r->server);
              
      /* sec_login_certify_identity() ensures that the correct security
       * server validated the password.
       */
      if (!sec_login_certify_identity(login_context, &dce_st))
        {
          dce_error_inq_text(dce_st, dce_error, &dce_error_st);
          log_debug(DEBUG_ERROR, pstrcat(r->pool,
                               "authenticate_dce_user: certify_identity failed for ", r->connection->user, " - ",
                               dce_error,
                               NULL),
                    r->server);

          /* The username/password failed certification. Remove whatever
           * login context was obtained, note the authorization failure
           * (which arranges for the correct headers to be returned to
           * the browser), and return authorization still required.
           * It would be nice to distinguish this failure from an invalid
           * username or password, but we don't have that mechanism.
           */
          sec_login_purge_context(&login_context, &dce_st);
          note_basic_auth_failure(r);
          return AUTH_REQUIRED;
        }
          
      /* Check what source provided the user's credentials. If they're
       * not network credentials, they won't do us much good.
       */
      if (auth_src != sec_login_auth_src_network)
        {
          log_debug(DEBUG_ERROR, pstrcat(r->pool,
                               "authenticate_dce_user: no network credentials for ", r->connection->user, " - ",
                               dce_error,
                               NULL),
                    r->server);

          /* The source must have been local (meaning the security
           * server couldn't be reached, and a local cache was used to
           * validate the password). This means we don't have network
           * credentials, and since the whole point of this is to access
           * files in DFS, we give up. Remove whatever login context was
           * obtained, note the authorization failure (which arranges for
           * the correct headers to be returned to the browser), and
           * return authorization still required. It would be nice to
           * distinguish this failure from an invalid username or
           * password, but we don't have that mechanism.
           */
          sec_login_purge_context(&login_context, &dce_st);
          note_basic_auth_failure(r);
          return AUTH_REQUIRED;
        }
          
      log_debug(DEBUG_INFO, "authenticate_dce_user: calling sec_login_set_context",
                r->server);
      
      /* Assign the new login context to the current process */
      sec_login_set_context(login_context, &dce_st);
      if (dce_st)
        {
          /* The context set failed. Abort and return authorization still required. */
          dce_error_inq_text(dce_st, dce_error, &dce_error_st);
          log_debug(DEBUG_ERROR, pstrcat(r->pool,
                                         "authenticate_dce_user: set_context failed for",
                                         r->connection->user, " - ",
                               dce_error,
                               NULL),
                    r->server);
          
          sec_login_purge_context(&login_context, &dce_st);
          note_basic_auth_failure(r);
          return AUTH_REQUIRED;
        }
      
#ifdef CACHING
      add_cached_context(r, &login_context, r->connection->user, sent_pw);
    }
#endif

          
  /* Save the address of the login context so dce_log_transaction
   * can purge/release it later.
   */
  set_module_config(r->request_config, &auth_dce_module, login_context);
                    

  /* The server might have failed to fill in the request_rec
   * structure due to permission errors. If the structure hasn't been
   * filled in, call the function (from http_request.c) again.
   */
  if (r->finfo.st_mode == 0)
    get_path_info(r);
          
          
  log_debug(DEBUG_INFO, "authenticate_dce_user: setting CGI environment variables",
            r->server);

          
  /* Set two environment variables for running CGIs. The first is
   * so the CGI can find its credentials, the second is for DCE
   * operations that require the user's password. We could check
   * and only set these if the request involves a CGI, but that would
   * be at least as much overhead as just setting them.
   */
  table_set(r->subprocess_env, "KRB5CCNAME", getenv("KRB5CCNAME"));
  table_set(r->subprocess_env, "DCEPW", sent_pw);  
  
  log_debug(DEBUG_INFO, "authenticate_dce_user: returning OK",
            r->server);

  /* Whee! */
  return OK;
}


/* Function to return OK for the group check if DCE authentication is
 * turned on
 */
int fake_dce_group_check (request_rec *r)
{
  /* Obtain the per-directory configuration for this request */  
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    get_module_config (r->per_dir_config, &auth_dce_module);

  
  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "fake_dce_group_check: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "fake_dce_group_check: called for filename ",
                       r->filename,
                       NULL),
            r->server);


  /* Is DCE authentication turned on for this request? If so, return OK.
   * if not, decline it */
  if (a->do_auth_dce)
    {
      log_debug(DEBUG_INFO, "check_dce_access: do_auth_dce set, returning OK",
                r->server);
      return OK;
    }
  else
    {
      log_debug(DEBUG_INFO, "check_dce_access: do_auth_dce not set, returning DECLINED",
                r->server);
      return DECLINED;
    }
}

/* Function to check whether the server has sufficient access for the request,
 * or whether it needs credentials
 */
int check_dce_access (request_rec *r)
{
  /* Unix structure for accessing file information */
  struct stat statbuf;

  /* Whether the object of the request is accessible */
  int accessible = 1;
  
  /* Obtain the per-directory configuration for this request */  
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    get_module_config (r->per_dir_config, &auth_dce_module);

  
  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "check_dce_access: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "check_dce_access: called for filename ",
                       r->filename,
                       NULL),
            r->server);


  /* Is DCE authentication turned on for this request? If not, decline it */
  if (!a->do_auth_dce)
    {
      log_debug(DEBUG_INFO, "check_dce_access: do_auth_dce not set, returning DECLINED",
                r->server);
      return DECLINED;
    }

    
  /* Check whether we can get to the file. First we stat() it, then we check
   * for the correct permissions for the type of request. If anything fails
   * due to permission errors, the file is not accessible. If we get any
   * other type of error, just say the file is accessible and let the
   * server handle it. We also need to check for an index file if the URL
   * is for a directory.
   */
  if(stat(r->filename, &statbuf))
    accessible = (errno != EACCES);
  else if (S_ISDIR(statbuf.st_mode))
    {
      if (r->uri[strlen(r->uri)-1] == '/')
        {
          char *indexes = (a->index_names) ? (a->index_names) : (DEFAULT_INDEX);
          char *slash = (r->filename[strlen(r->filename)-1] == '/') ? "" : "/";
          int access_required = R_OK | X_OK;
          
          while (*indexes)
            {
              char *index = getword_conf(r->pool, &indexes);
              char *filename = pstrcat(r->pool, r->filename, slash, index, NULL);

              if (!stat(filename, &statbuf))
                {
                  r->filename = filename;
                  access_required = R_OK;
                  break;
                }
            }

          if (access(r->filename, access_required))
            accessible = (errno != EACCES);
        }
    }
  else
    {
      if (access(r->filename, R_OK))
        accessible = (errno != EACCES);
    }
      

  if (accessible)
    {
      /* We can read the file without credentials. Set the request_config
       * variable so authenticate_dce_user() knows not to bother, and return
       * OK.
       */

      log_debug(DEBUG_INFO, "check_dce_access: file is accessible, returning OK",
                r->server);
      
      set_module_config(r->request_config, &auth_dce_module, NULL);
      return OK;
    }
  else
    {
      /* Permission error. Did the browser send an Authorization header? */
      if (table_get (r->headers_in, "Authorization"))
        {
          /* Yes, it did. Set the request_config variable so
           * authenticate_dce_user() knows to try and get credentials,
           * and then return OK.
           */
          log_debug(DEBUG_INFO, "check_dce_access: file not accessible, Authorization given, returning OK",
                    r->server);
          set_module_config(r->request_config, &auth_dce_module, (void *)1);
          return OK;
        }
      else
        {
          /* No Authorization header. Tell the browser it needs to send
           * authorization information.
           */
          log_debug(DEBUG_INFO, "check_dce_access: file not accessible, returning AUTH_REQUIRED",
                    r->server);
          note_basic_auth_failure(r);
          return AUTH_REQUIRED;
        }
    }
}


/* This function checks whether credentials were obtained for this request,
 * and if so, purges them
 */
int dce_log_transaction(request_rec *orig)
{
  /* DCE variable to hold pointer to login context */
  sec_login_handle_t login_context;

  /* DCE functions report their status in this variable */
  error_status_t dce_st;

  /* Pointer to the original request structure */
  request_rec *r = orig;

  /* Per-directory DCE authentication configuration variable */
  auth_dce_config_rec *a;

  log_debug(DEBUG_INFO, "dce_log_transaction: called", orig->server);


  /* A module log function is unique in that it doesn't get passed a single
   * request_rec structure, but rather a linked list. The original request
   * might have resulted in any number of internal redirects, so each
   * request_rec structure must be examined.
   */
  while(r)
    {
      log_debug(DEBUG_INFO, pstrcat(r->pool,
                           "dce_log_transaction: processing URI ",
                           r->uri,
                           NULL),
                r->server);

      log_debug(DEBUG_INFO, pstrcat(r->pool,
                           "dce_log_transaction: processing filename ",
                           r->filename,
                           NULL),
                r->server);

      /* Get the per-directory configuration information for this request */
      a = (auth_dce_config_rec *)
        get_module_config (r->per_dir_config, &auth_dce_module);

      
      /* If DCE authentication is turned on for this request, check if
       * there is any context to purge/release. If so, do it.
       */
      if (a->do_auth_dce)
        if ((login_context = (sec_login_handle_t)
             get_module_config(r->request_config, &auth_dce_module)))
          {
#ifdef CACHING
            log_debug(DEBUG_INFO, "dce_log_transaction: releasing a DCE login context",
                      r->server);
            sec_login_release_context(&login_context, &dce_st);
            /* DFS doesn't know you released the context, so you need to explicitly reset the PAG */
            afs_syscall(AFSCALL_RESETPAG);
#else
            log_debug(DEBUG_INFO, "dce_log_transaction: purging a DCE login context",
                      r->server);
            sec_login_purge_context(&login_context, &dce_st);
#endif
          }
      r = r->next;
    }
  return OK;
}


/* Standard module definition. Indicates which phases of the request
 * handling phase this module implements, and also what configuration file
 * commands it handles.
 */
module auth_dce_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_auth_dce_dir_config,	/* dir config creater */
   merge_dce_dir_configs,	/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   auth_dce_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   authenticate_dce_user,	/* check_user_id */
   fake_dce_group_check,	/* check auth */
   check_dce_access,		/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   dce_log_transaction		/* logger */
};


#ifdef CACHING

/* Structure to hold information for each cache entry */
typedef struct
{
  unsigned char md5_digest[16];
  idl_byte context_buf[CACHE_BUFSIZE];
  time_t expire_time;
} cache_entry_t;  

/* Cache data structures. The cache is implemented as a circular queue
 * embedded in an array.
 */
static cache_entry_t context_cache[CACHE_SIZE];
static int cache_head = 0;
static int cache_tail = 0;
static int cache_size = 0;

#ifdef CACHE_STATS
static unsigned int cache_accesses = 0;
static unsigned int cache_hits = 0;
#endif

static int find_cached_context(request_rec *r, sec_login_handle_t *login_context, char *username, char *password)
{
  int index;
  APACHE_MD5_CTX md5_context;
  unsigned char input_digest[16];
  time_t now = time(NULL);
  int count;
  error_status_t dce_st;
  /* String to store text for a given error code */
  dce_error_string_t dce_error;

  /* Variable to check the status of the error-code-to-text call */
  int dce_error_st;

  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "find_cached_context: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "find_cached_context: called for filename ",
                       r->filename,
                       NULL),
            r->server);

#ifdef CACHE_STATS
  cache_accesses++;
    
  if (!(cache_accesses % (CACHE_STAT_INTERVAL+1)))
    {
      char stat_buf[256];
      sprintf(stat_buf, "mod_auth_dce cache stats: Accesses = %d, Hits = %d, Hit percentage = %0.2f",
              cache_accesses-1, cache_hits, (float)cache_hits/(float)(cache_accesses-1));
      log_debug(DEBUG_CACHE, stat_buf, r->server);
    }

#endif


  while ((cache_size > 0) && (context_cache[cache_head].expire_time < now))
    {
      sec_login_import_context(CACHE_BUFSIZE, context_cache[cache_head].context_buf,
                               login_context, &dce_st);
      sec_login_purge_context(login_context, &dce_st);
      cache_head = ((cache_head + 1) % CACHE_SIZE);
      cache_size--;
    }

  /* Is the cache queue empty? */
  if (cache_size == 0)
    return FALSE;

      
  apache_MD5Init(&md5_context);
  apache_MD5Update(&md5_context, username, strlen(username));
  apache_MD5Update(&md5_context, password, strlen(password));
  apache_MD5Final(input_digest, &md5_context);

  
  index = ((cache_tail+CACHE_SIZE-1)%CACHE_SIZE);
  count = cache_size;

  while (count > 0)
    {
      if (!strncmp(input_digest, context_cache[index].md5_digest, 16))
        {
          /* Found it! Import it and return */
          sec_login_import_context(CACHE_BUFSIZE, context_cache[index].context_buf,
                                   login_context, &dce_st);
          if (!dce_st) sec_login_set_context(*login_context, &dce_st);          
          if (dce_st)
            {
              dce_error_inq_text(dce_st, dce_error, &dce_error_st);      
              log_debug(0, pstrcat(r->pool,
                                   "find_cached_context: import/set failed for ",
                                   username, 
                                   " - ",
                                   dce_error,
                                   NULL),
                        r->server);
              sec_login_purge_context(login_context, &dce_st);
              context_cache[index].md5_digest[0] = '\0';
              context_cache[index].expire_time = now;
              return FALSE;
            }
          
#ifdef CACHE_STATS
          cache_hits++;
#endif
          return TRUE;
        }
      index = (index+CACHE_SIZE-1)%CACHE_SIZE;
      count--;
    }

  return FALSE;
  
}

static void add_cached_context(request_rec *r, sec_login_handle_t *login_context, char *username, char *password)
{
  APACHE_MD5_CTX md5_context;
  time_t now = time(NULL);
  unsigned32 len_used, len_needed;
  error_status_t dce_st;
  /* String to store text for a given error code */
  dce_error_string_t dce_error;

  /* Variable to check the status of the error-code-to-text call */
  int dce_error_st;


  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "add_cached_context: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, pstrcat(r->pool,
                       "add_cached_context: called for filename ",
                       r->filename,
                       NULL),
            r->server);


  if (cache_size == CACHE_SIZE)
    {
      sec_login_handle_t tmp_context;

      sec_login_import_context(CACHE_BUFSIZE, context_cache[cache_head].context_buf,
                               &tmp_context, &dce_st);
      sec_login_purge_context(&tmp_context, &dce_st);
      
      cache_head = ((cache_head+1)%CACHE_SIZE);
      cache_size--;
    }

  apache_MD5Init(&md5_context);
  apache_MD5Update(&md5_context, username, strlen(username));
  apache_MD5Update(&md5_context, password, strlen(password));
  apache_MD5Final(context_cache[cache_tail].md5_digest, &md5_context);

  context_cache[cache_tail].expire_time = now + CACHE_TTL;

  sec_login_export_context(*login_context, CACHE_BUFSIZE, context_cache[cache_tail].context_buf,
                           &len_used, &len_needed, &dce_st);

  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);      
      log_debug(DEBUG_ERROR, pstrcat(r->pool,
                           "add_cached_context: export_context failed - ",
                           dce_error,
                           NULL),
                r->server);
      sec_login_purge_context(login_context, &dce_st);
      return;
    }

  cache_tail = (cache_tail+1)%CACHE_SIZE;
  cache_size++;

}

#endif
