/*
 * DCE Authentication Module for Apache HTTP Server
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1996,1997,1998,1999 Paul Henson -- see COPYRIGHT file for details
 *
 */

/* Include file to access DCE error text */
#include <dce/dce_error.h>

/* Include file to access DCE thread API */
#include <dce/pthread.h>

/* Include file to access DCE security login API */
#include <dce/sec_login.h>

/* Include files to access DCE security registry API */
#include <dce/binding.h>
#include <dce/pgo.h>

/* Include files to access Apache module API */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#include "ap_md5.h"

/* In AIX land, afs_syscall is called kafs_syscall.
 * Variety is the spice of life, after all....
 */
#ifdef AIX
#define afs_syscall kafs_syscall
#endif


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

/* Comment out following two defines to disable cache statistic generation */
#define CACHE_STATS
/* How often to output statistics */
#define CACHE_STAT_INTERVAL 500

/* Prototypes for cache interface */
static int find_cached_context(request_rec *r, sec_login_handle_t *, char *, char *);
static void add_cached_context(request_rec *r, sec_login_handle_t *, char *, char *);
static void delete_cached_contexts();
#endif

/* Prototype for context refreshing thread */
static pthread_addr_t refresh_context(pthread_addr_t arg);
     
/* We're still debugging... */
#define DEBUG 0

/* Production mode */
/* #undef DEBUG */


/* Define debugging log code */
#ifdef DEBUG
#define DEBUG_INFO 1
#define DEBUG_ERROR 0
#define DEBUG_CACHE 0
#define log_debug(L, X, Y) if (L <= DEBUG) ap_log_error_old(X, Y)
#else
#define log_debug(L, X, Y)
#endif

/* Structure to hold server-level configuration. Currently unused because
 * the Apache API won't allow us to set them in the stage needed.
 */
typedef struct dce_server_config_struct {
  char *placeholder; /* Needed because some compilers barf on empty structs */
} dce_server_config_rec;

/* Global variables to hold server-level configuration.  See previous comment */
static char *dce_user = NULL;
static char *dce_keytab = NULL;


/* Function to create and return an empty per-server module
 * configuration structure.
 */
static void *create_dce_server_config(pool *p, server_rec *s)
{
  return ap_pcalloc (p, sizeof(dce_server_config_rec));
}

/* Function that is called to merge two server configurations. */
static void *merge_dce_server_configs(pool *p, void *basev, void *addv)
{
  dce_server_config_rec *new = (dce_server_config_rec*)ap_pcalloc(p, sizeof(dce_server_config_rec));
  dce_server_config_rec *base = (dce_server_config_rec *)basev;
  dce_server_config_rec *add = (dce_server_config_rec *)addv;

  return new;
}

/* Function to handle DCEUser configuration directive */
static const char *set_user(cmd_parms *cmd, void *dv, const char *args)
{
  dce_user = ap_pstrcat(cmd->pool, args, NULL);

  return NULL;
}

/* Function to handle DCEKeytab configuration directive */
static const char *set_keytab(cmd_parms *cmd, void *dv, const char *args)
{
  dce_keytab = ap_pstrcat(cmd->pool, "FILE:", args, NULL);

  return NULL;
}


/* Define module structure for per-directory configuration. do_auth_dce
 * determines whether DCE authentication is turned on in a given directory,
 * do_auth_dfs controls whether the module uses DFS ACLs for authorization,
 * index_names lists the possible valid index files for a directory,
 * do_include_pw controls whether a CGI is passed the DCE password of the browser
 * when invoked, do_browser_creds controls whether we use the browser's creds or
 * not, and do_auth_authoritative determines whether the module should deny the
 * request if authentication fails or allow other modules to try.
 */
typedef struct auth_dce_config_struct {
  int do_auth_dce;
  int do_auth_dfs;
  int do_include_pw;
  int do_browser_creds;
  int do_auth_authoritative;
  char *index_names;
} auth_dce_config_rec;


/* Function to create and return an empty per-directory module
 * configuration structure.
 */
void *create_auth_dce_dir_config(pool *p, char *d)
{
    auth_dce_config_rec *new = (auth_dce_config_rec*)ap_pcalloc(p, sizeof(auth_dce_config_rec));
    new->do_browser_creds = 1;
    new->do_auth_authoritative = 1;
    
    return new;
}

/* Function that is called to merge two directory configurations. */
void *merge_dce_dir_configs(pool *p, void *basev, void *addv)
{
  auth_dce_config_rec *new = (auth_dce_config_rec*)ap_pcalloc(p, sizeof(auth_dce_config_rec));
  auth_dce_config_rec *base = (auth_dce_config_rec *)basev;
  auth_dce_config_rec *add = (auth_dce_config_rec *)addv;

  new->do_auth_dce = add->do_auth_dce;
  new->do_auth_dfs = add->do_auth_dfs;
  new->do_include_pw = add->do_include_pw;
  new->do_browser_creds = add->do_browser_creds;
  new->do_auth_authoritative = add->do_auth_authoritative;
  new->index_names = (add->index_names) ? (add->index_names) : (base->index_names);
  
  return new;
}


/* Function that handles the DCEDirectoryIndex configuration directive. */
static const char *set_indexes(cmd_parms *cmd, void *dv, const char *args)
{
  auth_dce_config_rec *d = (auth_dce_config_rec *)dv;

  d->index_names = ap_pstrcat(cmd->pool, args, NULL);

  return NULL;
}


/* This structure defines the configuration commands this module
 * is willing to handle.
 */
command_rec auth_dce_cmds[] = {
  { "AuthDCE", ap_set_flag_slot, (void *) XtOffsetOf(auth_dce_config_rec, do_auth_dce), OR_AUTHCFG, FLAG,
    "Perform DCE authentication in this directory?" },
  { "AuthDFS", ap_set_flag_slot, (void *) XtOffsetOf(auth_dce_config_rec, do_auth_dfs), OR_AUTHCFG, FLAG,
    "Use DFS ACLs for authorization in this directory?" },
  { "DCEIncludePW", ap_set_flag_slot, (void *) XtOffsetOf(auth_dce_config_rec, do_include_pw), OR_AUTHCFG, FLAG,
    "Include DCE password for CGIs run in this directory?" },
  { "DCEBrowserCreds", ap_set_flag_slot, (void *) XtOffsetOf(auth_dce_config_rec, do_browser_creds), OR_AUTHCFG, FLAG,
    "Attach browser's credentials when accessing files or running CGIs" },
  { "DCEUser", set_user, NULL, RSRC_CONF, RAW_ARGS,
    "DCE identity to run web server as" },
  { "DCEKeytab", set_keytab, NULL, RSRC_CONF, RAW_ARGS,
    "Keytab to use if different than default" },
  { "DCEAuthAuthoritative", ap_set_flag_slot, (void *) XtOffsetOf(auth_dce_config_rec, do_auth_authoritative), OR_AUTHCFG, FLAG,
    "Make DCE Authoritative" },
  { "DCEDirectoryIndex", set_indexes, NULL, OR_INDEXES, RAW_ARGS,
    "Set this identical to DirectoryIndex if set" },
  { NULL }
};


/* Declaration for the module configuration variable. The variable
 * is defined at this end of the module source code file.
 */
module auth_dce_module;

/* Variable to hold the server's DCE context if server is running authenticated. */
static sec_login_handle_t server_context = NULL;

/* Function to verify DCE username/password and obtain network credentials. */
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
    ap_get_module_config (r->per_dir_config, &auth_dce_module);

  
  log_debug(DEBUG_INFO, ap_pstrcat(r->pool, "authenticate_dce_user: called for URI ",
                       r->uri, NULL), r->server);

  log_debug(DEBUG_INFO, ap_pstrcat(r->pool, "authenticate_dce_user: called for filename ",
                       r->filename, NULL), r->server);


  /* Is DCE authentication turned on for this request? If not, decline it */
  if (!a->do_auth_dce)
    {
      log_debug(DEBUG_INFO, "authenticate_dce_user: do_auth_dce not set, returning DECLINED", r->server);
      return DECLINED;
    }

  
  /* If check_dfs_acl() didn't set the request_config variable, we don't
   * need credentials to complete the request. Return OK without bothering
   * with DCE calls.   */
  if (!ap_get_module_config(r->request_config, &auth_dce_module))
    {
      log_debug(DEBUG_INFO, "authenticate_dce_user: request_config not set, returning OK", r->server);
      return OK;
    }

  
  /* dce_log_transaction() checks the request_config variable when it tries
   * to purge or release the DCE context. Set it to NULL initially.
   */
  ap_set_module_config(r->request_config, &auth_dce_module, NULL);

  
  /* Call Apache function to extract the username and password information
   * from the request.
   */
  ap_get_basic_auth_pw (r, (const char **)&sent_pw);

  log_debug(DEBUG_INFO, ap_pstrcat(r->pool, "authenticate_dce_user: request made by user ",
                       r->connection->user, NULL), r->server);

  /* log_debug(DEBUG_INFO, ap_pstrcat(r->pool, "authenticate_dce_user: password is  ",
   *                               sent_pw, NULL), r->server);
   */
  

#ifdef CACHING
  if (!find_cached_context(r, &login_context, r->connection->user, sent_pw))
    {
#endif
      log_debug(DEBUG_INFO, "authenticate_dce_user: calling sec_login_setup_identity", r->server);
  
      /* sec_login_setup_identity() verifies that the username given is
       * correct and does the initial setup of the login context.
       */
      if (!sec_login_setup_identity((unsigned_char_p_t)r->connection->user, sec_login_no_flags,
                                    &login_context, &dce_st))
        {
          /* Invalid username. Clean up and return */
          dce_error_inq_text(dce_st, dce_error, &dce_error_st);
          log_debug(DEBUG_ERROR, ap_pstrcat(r->pool,
                               "authenticate_dce_user: sec_login_setup_identity failed for ", r->connection->user, " - ",
                               dce_error,
                               NULL),
                    r->server);
      
          sec_login_purge_context(&login_context, &dce_st);

	  /* If this module is authoratitive and authentication fails, refuse request and return
	   * AUTH_REQUIRED, otherwise deline the request and allow another module to give it a shot.
	   */
	  if (a->do_auth_authoritative)
	    {
	      ap_note_basic_auth_failure(r);
	      log_debug(DEBUG_INFO, "authenticate_dce_user: returning AUTH_REQUIRED",
			r->server);
	      return AUTH_REQUIRED;
	    }
	  else
	    {
	      log_debug(DEBUG_INFO, "authenticate_dce_user: DCEAuthAuthoritative off, returning DECLINED",
			r->server);
	      return DECLINED;
	    }
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
          log_debug(DEBUG_ERROR, ap_pstrcat(r->pool,
                               "authenticate_dce_user: sec_login_validate_ident failed for ", r->connection->user, " - ",
                               dce_error,
                               NULL),
                    r->server);
          sec_login_purge_context(&login_context, &dce_st);
          ap_note_basic_auth_failure(r);
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
          log_debug(DEBUG_ERROR, ap_pstrcat(r->pool,
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
          ap_note_basic_auth_failure(r);
          return AUTH_REQUIRED;
        }
          
      /* Check what source provided the user's credentials. If they're
       * not network credentials, they won't do us much good.
       */
      if (auth_src != sec_login_auth_src_network)
        {
          log_debug(DEBUG_ERROR, ap_pstrcat(r->pool,
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
          ap_note_basic_auth_failure(r);
          return AUTH_REQUIRED;
        }
          

#ifdef CACHING
      add_cached_context(r, &login_context, r->connection->user, sent_pw);
    }
#endif

  /* If we need to use the browser's credential for this request, attach them to this server process. */
  if (a->do_browser_creds)
    {
      log_debug(DEBUG_INFO, "authenticate_dce_user: calling sec_login_set_context",
		r->server);
      
      /* Assign the new login context to the current process */
      sec_login_set_context(login_context, &dce_st);
      if (dce_st)
	{
	  /* The context set failed. Abort and return authorization still required. */
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  log_debug(DEBUG_ERROR, ap_pstrcat(r->pool,
					    "authenticate_dce_user: set_context failed for",
					    r->connection->user, " - ",
					    dce_error,
					    NULL),
		    r->server);
	  
	  sec_login_purge_context(&login_context, &dce_st);
	  
	  if (server_context)
	    sec_login_set_context(server_context, &dce_st);
	  
	  ap_note_basic_auth_failure(r);
	  return AUTH_REQUIRED;
	}
    }
      
          
  /* Save the address of the login context so dce_log_transaction
   * can purge/release it later.
   */
  ap_set_module_config(r->request_config, &auth_dce_module, login_context);
                    

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
  ap_table_set(r->subprocess_env, "KRB5CCNAME", getenv("KRB5CCNAME"));

  /* Only set the password environment variable if explicitly configured
   * to do so.
   */
  if (a->do_include_pw)
    ap_table_set(r->subprocess_env, "DCEPW", sent_pw);  
  
  log_debug(DEBUG_INFO, "authenticate_dce_user: returning OK",
            r->server);

  /* Whee! */
  return OK;
}


/* Function to check the web server configuration to determine whether
 * the user is authorized for this request.
 */
int dce_check_authorization (request_rec *r)
{
  /* Obtain the per-directory configuration for this request */  
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    ap_get_module_config (r->per_dir_config, &auth_dce_module);

  /* DCE functions return status in this variable */
  error_status_t dce_st;
  
  /* String to store text for a given error code */
  dce_error_string_t dce_error;

  /* Variable to check the status of the error-code-to-text call */
  int dce_error_st;

  /* Variables to parse require directives */
  const char *require_list;
  char *require_type, *entity;
  const array_header *requires_array = ap_requires(r);
  require_line *require_lines;

  /* Variables to control loops */
  int index;
  int done = 0;

  /* Store the value to be returned from this function */
  int retval = OK;

  
  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                       "dce_check_authorization: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                       "dce_check_authorization: called for filename ",
                       r->filename,
                       NULL),
            r->server);


  /* Is DCE authentication turned on for this request? If not, decline it */
  if (!a->do_auth_dce)
    {
      log_debug(DEBUG_INFO, "dce_check_authorization: do_auth_dce not set, returning DECLINED", r->server);
      return DECLINED;
    }


  /* Retrieve the relevant require information for this request */
  if (!requires_array)
    {
      /* Assume no require information is the same as "require valid-user",
       * and return OK. */
      log_debug(DEBUG_INFO, "dce_check_authorization: no requires line, returning OK", r->server);
      return (OK);
    }


  /* Loop through each require entry */
  require_lines = (require_line *)requires_array->elts;
  for(index = 0; (index < requires_array->nelts) && (!done); index++)
    {
      /* If the require entry doesn't apply to this request, skip the loop */
      if (!(require_lines[index].method_mask & (1 << r->method_number)))
	continue;

      /* We've found a require entry that limits access for this request. Assume
       * request is forbidden or declined unless we determine otherwise.
       */
      retval = (a->do_auth_authoritative) ? (FORBIDDEN) : (DECLINED);

      /* Get require type */
      require_list = require_lines[index].requirement;
      require_type = ap_getword_white(r->pool, &require_list);

      if(!strcmp(require_type, "valid-user"))
	{
	  /* If the type is valid-user, anybody is fine, so return OK. */
	  retval = OK; done = 1;
	  break;
	}
      else if(!strcmp(require_type, "user"))
	{
	  /* If the type is user, check all users listed on the require entry to
	   * see if the requesting user is one of them.
	   */
	  while(*require_list)
	    {
	      entity = ap_getword_conf(r->pool, &require_list);
	      if(!strcmp(entity, r->connection->user))
		{
		  /* Yep, he's there. Return OK. */
		  retval = OK; done = 1;
		  break;
		}
	    }
	}
        else if(!strcmp(require_type, "group"))
	  {
	    /* If the type is group, check each group listed on the require entry to
	     * see if the requesting user is a member.
	     */

            while(*require_list)
	      {
		entity = ap_getword_conf(r->pool, &require_list);
		if(sec_rgy_pgo_is_member(sec_rgy_default_handle, sec_rgy_domain_group, (unsigned_char_p_t)entity,
					 (unsigned_char_p_t)r->connection->user, &dce_st))
		  {
		    retval = OK; done = 1;
		    break;
		  }
	      }
	  }
    }

  /* Retval is either OK if none of the require entries matched this request,
   * FORBIDDEN/DECLINED if an entry matched and didn't allow the user, or OK if an entry
   * matched and did allow this user.
   */
  return retval;
}


/* Function to check the DFS ACL for the request and see if the server
 * requires authentication to access it. Only relevant if AuthDFS is
 * enabled.
 */
int check_dfs_acl (request_rec *r)
{
  /* Unix structure for accessing file information */
  struct stat statbuf;

  /* Whether the object of the request is accessible */
  int accessible = 1;
  
  /* Obtain the per-directory configuration for this request */  
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    ap_get_module_config (r->per_dir_config, &auth_dce_module);

  
  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                       "check_dfs_acl: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                       "check_dfs_acl: called for filename ",
                       r->filename,
                       NULL),
            r->server);


  /* Is DCE authentication turned on for this request? If not, decline it */
  if (!a->do_auth_dce)
    {
      log_debug(DEBUG_INFO, "check_dfs_acl: do_auth_dce not set, returning DECLINED",
                r->server);
      return DECLINED;
    }


  /* If AuthDFS is not set for this request, then request authentication regardless
   * of file protections.
   */
  if (!a->do_auth_dfs)
    accessible = 0;
  else
    {
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
	      const char *indexes = (a->index_names) ? (a->index_names) : (DEFAULT_INDEX);
	      char *slash = (r->filename[strlen(r->filename)-1] == '/') ? "" : "/";
	      int access_required = R_OK | X_OK;
	      
	      while (*indexes)
		{
		  char *index = ap_getword_conf(r->pool, &indexes);
		  char *filename = ap_pstrcat(r->pool, r->filename, slash, index, NULL);
		  
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
    }

  if (accessible)
    {
      /* We can read the file without credentials. Set the request_config
       * variable so authenticate_dce_user() knows not to bother, and return
       * OK.
       */

      log_debug(DEBUG_INFO, "check_dfs_acl: file is accessible, returning OK",
                r->server);
      
      ap_set_module_config(r->request_config, &auth_dce_module, NULL);
      return OK;
    }
  else
    {
      /* Permission error. Did the browser send an Authorization header? */
      if (ap_table_get (r->headers_in, "Authorization"))
        {
          /* Yes, it did. Set the request_config variable so
           * authenticate_dce_user() knows to try and get credentials,
           * and then return OK.
           */
          log_debug(DEBUG_INFO, "check_dfs_acl: file not accessible, Authorization given, returning OK",
                    r->server);
          ap_set_module_config(r->request_config, &auth_dce_module, (void *)1);
          return OK;
        }
      else
        {
          /* No Authorization header. Tell the browser it needs to send
           * authorization information.
           */
          log_debug(DEBUG_INFO, "check_dfs_acl: file not accessible, returning AUTH_REQUIRED",
                    r->server);
          ap_note_basic_auth_failure(r);
          return AUTH_REQUIRED;
        }
    }
}


/* This function checks whether credentials were obtained for this request,
 * and if so, purges them or releases them, depending on whether caching is
 * enabled.
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
      log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                           "dce_log_transaction: processing URI ",
                           r->uri,
                           NULL),
                r->server);

      log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                           "dce_log_transaction: processing filename ",
                           r->filename,
                           NULL),
                r->server);

      /* Get the per-directory configuration information for this request */
      a = (auth_dce_config_rec *)
        ap_get_module_config (r->per_dir_config, &auth_dce_module);

      
      /* If DCE authentication is turned on for this request and browser credentials
       * were attached, check if there is any context to purge/release. If so, do it.
       */
      if (a->do_auth_dce && a->do_browser_creds)
        if ((login_context = (sec_login_handle_t)
             ap_get_module_config(r->request_config, &auth_dce_module)))
          {
#ifdef CACHING
            log_debug(DEBUG_INFO, "dce_log_transaction: unsetting KRB5CCNAME",
                      r->server);
	    putenv("KRB5CCNAME=");

            /* Explicitly reset the PAG */
            afs_syscall(AFSCALL_RESETPAG);
#else
            log_debug(DEBUG_INFO, "dce_log_transaction: purging a DCE login context",
                      r->server);
            sec_login_purge_context(&login_context, &dce_st);
#endif

	    if (server_context) {
	      sec_login_set_context(server_context, &dce_st);
	      if (dce_st)
		log_debug(DEBUG_ERROR, "dce_log_transaction: failed to restore server context", r->server);
	    }
	      
          }
      r = r->next;
    }
  return OK;
}

/* Function that is run to initialize each child process. Obtain credentials via keytab
 * if Web server is to run authenticated. This function is run after the process has
 * already changed its UID, so the keytab must be readable by the Unix identity of the
 * Web server. Each child obtains and refreshes its own credentials; while it would be
 * more efficient for the parent to do so, conflicts between threads and fork() prevent
 * this. If an error condition occurs, it is logged and the child exits. This could lead
 * to a wildly spinning parent if a condition arises that causes authentication to
 * continually fail.
 */
static void dce_process_initialize(server_rec *s, pool *p)
{
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  sec_login_auth_src_t auth_src;
  boolean32 reset_passwd;
  unsigned32 kvno_worked;
  pthread_t refresh_thread;
  
  log_debug(DEBUG_INFO, "dce_process_initialize: called.", s);

  if (dce_user)
    {
      log_debug(DEBUG_INFO, ap_pstrcat(p, "dce_process_initialize: user = ", dce_user, NULL), s);
      log_debug(DEBUG_INFO, ap_pstrcat(p, "dce_process_initialize: keytab = ", dce_keytab, NULL), s);
      
      if (!sec_login_setup_identity ((unsigned_char_p_t)dce_user,
				     sec_login_no_flags, &server_context, &dce_st))
	{
	 dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	 log_debug(DEBUG_ERROR, ap_pstrcat(p,
					   "dce_process_initialize: sec_login_setup_identity failed for ", dce_user, " - ",
 					   dce_error, NULL), s);
	 exit(1);
	}
      sec_login_valid_from_keytable (server_context, rpc_c_authn_dce_secret, dce_keytab, (unsigned32) NULL, &kvno_worked,
				     &reset_passwd, &auth_src, &dce_st);
      if (dce_st != error_status_ok)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  log_debug(DEBUG_ERROR, ap_pstrcat(p,
					    "dce_process_initialize: sec_login_valid_from_keytable failed for ", dce_user, " - ",
					    dce_error, NULL), s);
	  sec_login_purge_context(&server_context, &dce_st);
	  exit(1);
	}
      if (!sec_login_certify_identity(server_context, &dce_st))
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  log_debug(DEBUG_ERROR, ap_pstrcat(p,
					    "dce_process_initialize: sec_login_certify_identity failed for ", dce_user, " - ",
					    dce_error, NULL), s);
	  sec_login_purge_context(&server_context, &dce_st);
	  exit(1);
	}
      if (auth_src != sec_login_auth_src_network)
	{
	  log_debug(DEBUG_ERROR, ap_pstrcat(p,
					    "dce_process_initialize: no network credentials for ", dce_user, " - ",
					    dce_error, NULL), s);
	  sec_login_purge_context(&server_context, &dce_st);
	  exit(1);
	}

      sec_login_set_context(server_context, &dce_st);

      if (dce_st != error_status_ok)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  log_debug(DEBUG_ERROR, ap_pstrcat(p,
					    "dce_process_initialize: sec_login_set_context failed for ", dce_user, " - ",
					    dce_error, NULL), s);
	  sec_login_purge_context(&server_context, &dce_st);
	  exit(1);
	}

      /* Create a thread to refresh the obtained context. */
      if (pthread_create(&refresh_thread, pthread_attr_default, refresh_context,
			 (pthread_addr_t) NULL))
	{
	  log_debug(DEBUG_ERROR, "dce_process_initialize: refresh pthread create failed", s);
	  exit(1);
	}
	
      pthread_detach(&refresh_thread);

    }
}

/* Function that is run when a child process exits. It cleans up any contexts
 * left in the cache, and also the server context if need be.
 */
static void dce_process_cleanup(server_rec *s, pool *p)
{
#ifdef CACHING
  delete_cached_contexts();
#endif

  if (server_context)
    {
      error_status_t dce_st;
      
      sec_login_purge_context(&server_context, &dce_st);
    }	
}

/* Standard module definition. Indicates which phases of the request
 * handling phase this module implements, and also what configuration file
 * commands it handles.
 */
module auth_dce_module = {
   STANDARD_MODULE_STUFF,
   NULL,	        	/* initializer */
   create_auth_dce_dir_config,	/* dir config creater */
   merge_dce_dir_configs,	/* dir merger --- default is to override */
   create_dce_server_config,	/* server config */
   merge_dce_server_configs,	/* merge server config */
   auth_dce_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   authenticate_dce_user,	/* check_user_id */
   dce_check_authorization,	/* check auth */
   check_dfs_acl,		/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   dce_log_transaction,		/* logger */
   NULL,                        /* [3] header parser */
   dce_process_initialize,      /* process initializer */
   dce_process_cleanup,         /* process exit/cleanup */
   NULL                         /* [1] post read_request handling */
};

/* Function that is spawned as a separate thread to handle context refreshing
 * if the Web server is running authenticated.
 */
static pthread_addr_t refresh_context(pthread_addr_t arg)
{
  signed32 expiration_time;
  struct timeval now;
  struct timespec sleep_interval;
  error_status_t dce_st;
  sec_login_auth_src_t auth_src;
  unsigned32 kvno_worked;
  boolean32 reset_passwd;
 
  while (1)
    {
      sec_login_get_expiration(server_context, &expiration_time, &dce_st);
      
      gettimeofday (&now, 0);

      sleep_interval.tv_sec = expiration_time - now.tv_sec - 10 * 60;
      sleep_interval.tv_nsec = 0;
      
      pthread_delay_np (&sleep_interval);
	
      sec_login_refresh_identity (server_context, &dce_st);
      
      sec_login_valid_from_keytable (server_context, rpc_c_authn_dce_secret, dce_keytab, (unsigned32) NULL, &kvno_worked,
				     &reset_passwd, &auth_src, &dce_st);
    }				   
}
  

#ifdef CACHING

/* Structure to hold information for each cache entry */
typedef struct
{
  unsigned char md5_digest[16];
  sec_login_handle_t login_context;
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
  AP_MD5_CTX md5_context;
  unsigned char input_digest[16];
  time_t now = time(NULL);
  int count;
  error_status_t dce_st;


  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                       "find_cached_context: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
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
      sec_login_purge_context(&context_cache[cache_head].login_context, &dce_st);
      cache_head = ((cache_head + 1) % CACHE_SIZE);
      cache_size--;
    }

  /* Is the cache queue empty? */
  if (cache_size == 0)
    return FALSE;

      
  ap_MD5Init(&md5_context);
  ap_MD5Update(&md5_context, (const unsigned char *)username, strlen(username));
  ap_MD5Update(&md5_context, (const unsigned char *)password, strlen(password));
  ap_MD5Final(input_digest, &md5_context);

  
  index = ((cache_tail+CACHE_SIZE-1)%CACHE_SIZE);
  count = cache_size;

  while (count > 0)
    {
      if (!strncmp((const char *)input_digest, (const char *)context_cache[index].md5_digest, 16))
        {
          /* Found it! Import it and return */

          *login_context = context_cache[index].login_context;
	  
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
  AP_MD5_CTX md5_context;
  time_t now = time(NULL);
  error_status_t dce_st;


  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                       "add_cached_context: called for URI ",
                       r->uri,
                       NULL),
            r->server);
  log_debug(DEBUG_INFO, ap_pstrcat(r->pool,
                       "add_cached_context: called for filename ",
                       r->filename,
                       NULL),
            r->server);


  if (cache_size == CACHE_SIZE)
    {
      sec_login_purge_context(&context_cache[cache_head].login_context, &dce_st);
      
      cache_head = ((cache_head+1)%CACHE_SIZE);
      cache_size--;
    }

  ap_MD5Init(&md5_context);
  ap_MD5Update(&md5_context, (const unsigned char *)username, strlen(username));
  ap_MD5Update(&md5_context, (const unsigned char *)password, strlen(password));
  ap_MD5Final(context_cache[cache_tail].md5_digest, &md5_context);

  context_cache[cache_tail].expire_time = now + CACHE_TTL;

  context_cache[cache_tail].login_context = *login_context;

  cache_tail = (cache_tail+1)%CACHE_SIZE;
  cache_size++;

}

static void delete_cached_contexts()
{
  error_status_t dce_st;
  
  while (cache_size > 0)
    {
      sec_login_purge_context(&context_cache[cache_head].login_context, &dce_st);
      cache_head = ((cache_head + 1) % CACHE_SIZE);
      cache_size--;
    }
}
  
#endif
