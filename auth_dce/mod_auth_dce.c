/*
 * DCE Authentication Module for Apache HTTP Server
 *
 * Paul B. Henson <henson@acm.org>
 *
 * Copyright (c) 1996-2001 Paul B. Henson -- see COPYRIGHT file for details
 *
 */

/* MODULE-DEFINITION-START
 * Name: auth_dce
 * ConfigStart

    case "$PLAT" in
    
      *-ibm-aix4.*)
        echo "  mod_auth_dce: Note - context caching not supported on this platform."
        CC=xlC_r4
	CFLAGS="$CFLAGS -DNO_CACHING"
        LDFLAGS="$LDFLAGS -ldce -lm"
        ;;

      *-dec-osf*)
        echo "  mod_auth_dce: Note - context caching not supported on this platform."
	CFLAGS="$CFLAGS -std -threads -DNO_CACHING"
	LDFLAGS="$LDFLAGS -threads"
        LIBS="$LIBS -ldce -lm"
        ;;
      
      *-solaris2*)
        CFLAGS="$CFLAGS -D_REENTRANT"
        case "$PLATOSVERS" in
            2[012345]*)
                LIBS="$LIBS -ldce -lthread -lsocket -lnsl -lm"
                ;;
            2[678]*)
                LIBS="$LIBS -ldce -lpthread -lsocket -lnsl"
                ;;
	    *)
	        echo "  mod_auth_dce: This version of Solaris is not currently supported."
		exit 1
		;;
        esac
	;;

      *)
	echo "  mod_auth_dce: I don't know how to compile DCE applications on this platform."
	exit 1
	;;
	
    esac

 * ConfigEnd
 * MODULE-DEFINITION-END
 */

#if defined(HPUX) || defined(HPUX10) || defined(HPUX11) /* I guess HPSUX just had to be different */
#include <pthread.h>
#else
#include <dce/pthread.h>
#endif

#include <dce/dce_error.h>
#include <dce/sec_login.h>
#include <dce/binding.h>
#include <dce/pgo.h>
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#include "mod_auth_dce.h"


#ifndef NO_CACHING
#ifdef SOLARIS2
static char krb5_env[] = "KRB5CCNAME=FILE:/opt/dcelocal/var/security/creds/dcecred_XXXXXXXX";
static char *krb5_env_pag = krb5_env+57;
#else
#error Credential cache directory not known for this platform.
#endif
static unsigned32 server_pag = 0;
#endif

#ifndef WITH_DFS
static unsigned long sec_login_inq_pag_no_dfs(void *dummy, error_status_t *dce_st)
{
  char *krb5ccname = getenv("KRB5CCNAME");
  *dce_st = 0;
  
  if (krb5ccname)
    {
      int len = strlen(krb5ccname);
      if (len >= 8)
	return (unsigned long)strtol(krb5ccname + len - 8, (char **)NULL, 16);
    }
  
  return 0;
}
#define sec_login_inq_pag(X, Y) sec_login_inq_pag_no_dfs(X, Y)
#define installpag(X)
#define resetpag()
#endif

static sec_login_handle_t server_context = NULL;


server_config_rec auth_dce_server_config = {
  NULL,  /* default user */
  NULL,  /* default keytab */
  0,     /* default certify_identity */
#ifndef NO_CACHING
  1000,  /* default cache_buckets */
  7200,  /* default cache_graceperiod */
  21600, /* default cache_lifetime */
  14400, /* default cache_max_idle */
  1800   /* default cache_sweep_interval */
#endif
};


static pthread_addr_t refresh_context(pthread_addr_t arg)
{
  signed32 expiration_time;
  time_t now;
  struct timespec sleep_interval;
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  sec_login_auth_src_t auth_src;
  unsigned32 kvno_worked;
  boolean32 reset_passwd;
  server_rec *s = (server_rec *)arg;

  DEBUG_S("auth_dce.refresh_context: beginning context refresh loop");
  
  while (1)
    {
      now = time(NULL);

      sec_login_get_expiration(server_context, &expiration_time, &dce_st);
      if (dce_st && (dce_st != sec_login_s_not_certified))
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
		       "auth_dce.refresh_context: sec_login_get_expiration failed - %s (%d)", dce_error, dce_st);
	  expiration_time = now + 20 * 60;
	}

      DEBUG_S("auth_dce.refresh_context: context expires at time %d", expiration_time);
      
      sleep_interval.tv_sec = expiration_time - now - 10 * 60;
      sleep_interval.tv_nsec = 0;
      
      pthread_delay_np(&sleep_interval);
	
      sec_login_refresh_identity(server_context, &dce_st);
      if (dce_st)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
		       "auth_dce.refresh_context: sec_login_refresh_identity failed - %s (%d)", dce_error, dce_st);
	}
      
      sec_login_valid_from_keytable(server_context, rpc_c_authn_dce_secret, auth_dce_server_config.keytab, (unsigned32) NULL, &kvno_worked,
				    &reset_passwd, &auth_src, &dce_st);
      if (dce_st)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
		       "auth_dce.refresh_context: sec_login_valid_from_keytable failed - %s (%d)", dce_error, dce_st);
	}
    }		   
  return 0;
}

#ifndef NO_CACHING
void auth_dce_purge_context(server_rec *s, unsigned long pag)
{
  sec_login_handle_t login_context;
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;

  DEBUG_S("auth_dce.purge_context called for pag %08x", pag);
  
  sec_login_context_from_pag(pag, &login_context, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
		   "auth_dce.purge_context: sec_login_context_from_pag failed - %s (%d)", dce_error, dce_st);
      return;
    }
  
  sec_login_purge_context(&login_context, &dce_st);
}	
#endif

static void *create_server_config(pool *p, server_rec *s)
{
  return ap_pcalloc (p, sizeof(server_config_rec));
}

static void *merge_server_configs(pool *p, void *basev, void *addv)
{
  server_config_rec *new = (server_config_rec*)ap_pcalloc(p, sizeof(server_config_rec));
  server_config_rec *base = (server_config_rec *)basev;
  server_config_rec *add = (server_config_rec *)addv;
  
  return new;
}

static const char *set_user(cmd_parms *cmd, void *dv, char *word1)
{
  auth_dce_server_config.user = (word1) ? ap_pstrdup(cmd->pool, word1) : NULL;
  return NULL;
}

static const char *set_keytab(cmd_parms *cmd, void *dv, char *word1)
{
  auth_dce_server_config.keytab = ap_pstrcat(cmd->pool, "FILE:", word1, NULL);
  return NULL;
}

static const char *set_certify_identity(cmd_parms *cmd, void *mconfig, int bool)
{
  auth_dce_server_config.certify_identity = bool;
  return NULL;
}

#ifndef NO_CACHING
static const char *set_cache_buckets(cmd_parms *cmd, void *dv, char *word1)
{
  auth_dce_server_config.cache_buckets = atoi(word1);
  if (auth_dce_server_config.cache_buckets < 1 || auth_dce_server_config.cache_buckets > 50000)
    return "auth_dce: invalid cache_buckets value";
  
  return NULL;
}

static const char *set_cache_graceperiod(cmd_parms *cmd, void *dv, char *word1)
{
  auth_dce_server_config.cache_graceperiod = atoi(word1);
  if (auth_dce_server_config.cache_graceperiod < 0)
    return "auth_dce: invalid negative cache_graceperiod";
  
  return NULL;
}

static const char *set_cache_lifetime(cmd_parms *cmd, void *dv, char *word1)
{
  auth_dce_server_config.cache_lifetime = atoi(word1);
  if (auth_dce_server_config.cache_lifetime < 3600)
    return "auth_dce: invalid cache_buckets value < 3600 seconds";
  
  return NULL;
}

static const char *set_cache_max_idle(cmd_parms *cmd, void *dv, char *word1)
{
  auth_dce_server_config.cache_max_idle = atoi(word1);
  if (auth_dce_server_config.cache_max_idle < 0)
    return "auth_dce: invalid cache_max_idle < 0";
  
  return NULL;
}

static const char *set_cache_sweep_interval(cmd_parms *cmd, void *dv, char *word1)
{
  auth_dce_server_config.cache_sweep_interval = atoi(word1);
  if (auth_dce_server_config.cache_sweep_interval < 300)
    return "auth_dce: invalid cache_sweep_interval < 300 seconds";
  
  return NULL;
}
#endif

static const char *set_indexes(cmd_parms *cmd, void *dv, const char *args)
{
  dir_config_rec *dir_config = (dir_config_rec *)dv;
  dir_config->index_names = ap_pstrcat(cmd->pool, args, NULL);
  return NULL;
}

static void *create_dir_config(pool *p, char *d)
{
    dir_config_rec *new = (dir_config_rec*)ap_pcalloc(p, sizeof(dir_config_rec));
    new->impersonate_browser = 1;
    new->authoritative = 1;
    
    return new;
}

static void *merge_dir_configs(pool *p, void *basev, void *addv)
{
  dir_config_rec *new = (dir_config_rec*)ap_pcalloc(p, sizeof(dir_config_rec));
  dir_config_rec *base = (dir_config_rec *)basev;
  dir_config_rec *add = (dir_config_rec *)addv;

  new->active = add->active;
#ifdef WITH_DFS
  new->dfs_authorization = add->dfs_authorization;
#endif
  new->include_pw = add->include_pw;
  new->impersonate_browser = add->impersonate_browser;
  new->authoritative = add->authoritative;
  new->index_names = (add->index_names) ? (add->index_names) : (base->index_names);
  
  return new;
}


static command_rec cmds[] = {
  { "AuthDCE", ap_set_flag_slot, (void *) XtOffsetOf(dir_config_rec, active), OR_AUTHCFG, FLAG,
    "Perform DCE authentication in this directory?" },

#ifdef WITH_DFS
  { "AuthDCEDFSAuthorization", ap_set_flag_slot, (void *) XtOffsetOf(dir_config_rec, dfs_authorization), OR_AUTHCFG, FLAG,
    "Use DFS ACLs for authorization in this directory?" },
#endif
  
  { "AuthDCEIncludePW", ap_set_flag_slot, (void *) XtOffsetOf(dir_config_rec, include_pw), OR_AUTHCFG, FLAG,
    "Include DCE password for CGIs run in this directory?" },
  
  { "AuthDCEImpersonateBrowser", ap_set_flag_slot, (void *) XtOffsetOf(dir_config_rec, impersonate_browser), OR_AUTHCFG, FLAG,
    "Attach browser's credentials when accessing files or running CGIs?" },
  
  { "AuthDCEUser", set_user, NULL, RSRC_CONF, TAKE1,
    "DCE identity to run web server as" },
  
  { "AuthDCEKeytab", set_keytab, NULL, RSRC_CONF, TAKE1,
    "Keytab to use if different than default" },
  
  { "AuthDCEAuthoritative", ap_set_flag_slot, (void *) XtOffsetOf(dir_config_rec, authoritative), OR_AUTHCFG, FLAG,
    "Make DCE Authoritative" },
  
  { "AuthDCEDirectoryIndex", set_indexes, NULL, OR_INDEXES, RAW_ARGS,
    "Set this identical to DirectoryIndex if set" },
  
  { "AuthDCECertifyIdentity", set_certify_identity, NULL, RSRC_CONF, FLAG,
    "Certify DCE Identity" },

#ifndef NO_CACHING
  { "AuthDCECacheBuckets", set_cache_buckets, NULL, RSRC_CONF, TAKE1,
    "Number of buckets in credential hash table" },
  
  { "AuthDCECacheGracePeriod", set_cache_graceperiod, NULL, RSRC_CONF, TAKE1,
    "Time in seconds" },
 
  { "AuthDCECacheLifetime", set_cache_lifetime, NULL, RSRC_CONF, TAKE1,
    "Time in seconds after which credentials are removed" },
  
  { "AuthDCECacheMaxIdle", set_cache_max_idle, NULL, RSRC_CONF, TAKE1,
    "Time in seconds after which unused credentials are considered idle" },
  
  { "AuthDCECacheSweepInterval", set_cache_sweep_interval, NULL, RSRC_CONF, TAKE1,
    "Frequency in seconds to sweep cache for credential removal" },
#endif
  
  { NULL }
};


module auth_dce_module;

static int authenticate(request_rec *r)
{
  char *sent_pw;
  sec_login_handle_t login_context;
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  sec_login_auth_src_t auth_src;
  sec_passwd_rec_t pw_entry;
  sec_passwd_str_t dce_pw;
  boolean32 reset_passwd;
  request_config_rec *request_config;
  
  dir_config_rec *dir_config = (dir_config_rec *)ap_get_module_config(r->per_dir_config, &auth_dce_module);

  DEBUG_R("auth_dce.authenticate: called for URI %s", r->uri);
  DEBUG_R("auth_dce.authenticate: called for filename %s", r->filename);

  if (!dir_config->active)
    {
      if (server_context)
	ap_table_set(r->subprocess_env, "KRB5CCNAME", getenv("KRB5CCNAME"));
      
      DEBUG_R("auth_dce.authenticate: active not set, returning DECLINED");
      
      return DECLINED;
    }

#ifdef WITH_DFS
  if (dir_config->dfs_authorization)
    {
      struct stat statbuf;
      int accessible = 1;

      if(stat(r->filename, &statbuf))
	accessible = (errno != EACCES);
      else
	{
	  int access_required = R_OK;
	  
	  if (S_ISDIR(statbuf.st_mode))
	    if (r->uri[strlen(r->uri)-1] == '/')
	      {
		const char *indexes = (dir_config->index_names) ? (dir_config->index_names) : (DEFAULT_INDEX);
		char *slash = (r->filename[strlen(r->filename)-1] == '/') ? "" : "/";
		access_required |= X_OK;
		
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
	      }
	    else
	      return OK; /* request for directory with no trailing slash, allow redirect without authentication */

	  if (access(r->filename, access_required))
	    accessible = (errno != EACCES);
	}

      if (accessible)
	{
	  DEBUG_R("auth_dce.authenticate: file is accessible, returning OK");
	  ap_set_module_config(r->request_config, &auth_dce_module, NULL);

	  if (server_context)
	    ap_table_set(r->subprocess_env, "KRB5CCNAME", getenv("KRB5CCNAME"));

	  return OK;
	}
    }
#endif
  
  if (!(ap_table_get(r->headers_in, r->proxyreq != STD_PROXY ? "Authorization" : "Proxy-Authorization")))
    { 
      DEBUG_R("auth_dce.authenticate: authorization not provided, returning AUTH_REQUIRED");
      ap_note_basic_auth_failure(r);
      
      return AUTH_REQUIRED;
    }

  ap_set_module_config(r->request_config, &auth_dce_module, (void *)ap_pcalloc(r->pool, sizeof(request_config_rec)));
  request_config = (request_config_rec *)ap_get_module_config(r->request_config, &auth_dce_module);
  
  ap_get_basic_auth_pw(r, (const char **)&sent_pw);

  DEBUG_R("auth_dce.authenticate: request made by user %s", r->connection->user);
  
#ifndef NO_CACHING
  auth_dce_find_cached_context(r, request_config, r->connection->user, sent_pw);

  if (!request_config->pag)
    {
#endif

      DEBUG_R("auth_dce.authenticate: calling sec_login_setup_identity");
  
      if (!sec_login_setup_identity((unsigned_char_p_t)r->connection->user, sec_login_no_flags,
                                    &login_context, &dce_st))
        {
          dce_error_inq_text(dce_st, dce_error, &dce_error_st);
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.authenticate: sec_login_setup_identity failed for %s - %s (%d)", r->connection->user, dce_error, dce_st);
      
	  if (dir_config->authoritative)
	    {
	      ap_note_basic_auth_failure(r);
	      DEBUG_R("auth_dce.authenticate: returning AUTH_REQUIRED");
	      
	      return AUTH_REQUIRED;
	    }
	  else
	    {
	      DEBUG_R("auth_dce.authenticate: AuthDCEAuthoritative off, returning DECLINED");
	      
	      return DECLINED;
	    }
	}

      pw_entry.version_number = sec_passwd_c_version_none;
      pw_entry.pepper = NULL;
      pw_entry.key.key_type = sec_passwd_plain;
          
      strncpy( (char *)dce_pw, sent_pw, sec_passwd_str_max_len);
      dce_pw[sec_passwd_str_max_len] = '\0';
      pw_entry.key.tagged_union.plain = &(dce_pw[0]);

      DEBUG_R("auth_dce.authenticate: calling sec_login_validate_identity");
      
      if (!sec_login_validate_identity(login_context, &pw_entry, &reset_passwd,
                                       &auth_src, &dce_st))
        {
          dce_error_inq_text(dce_st, dce_error, &dce_error_st);
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.authenticate: sec_login_validate_identity failed for %s - %s (%d)", r->connection->user, dce_error, dce_st);
	  
          sec_login_purge_context(&login_context, &dce_st);
          ap_note_basic_auth_failure(r);
          DEBUG_R("auth_dce.authenticate: returning AUTH_REQUIRED");
	  
          return AUTH_REQUIRED;
        }
        
      if (auth_dce_server_config.certify_identity)
	{
	  DEBUG_R("auth_dce.authenticate: calling sec_login_certify_identity");
	  
	  if (!sec_login_certify_identity(login_context, &dce_st))
	    {
	      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			    "auth_dce.authenticate: sec_login_certify_identity failed for %s - %s (%d)", r->connection->user, dce_error, dce_st);
	      
	      sec_login_purge_context(&login_context, &dce_st);
	      ap_note_basic_auth_failure(r);
	      DEBUG_R("auth_dce.authenticate: returning AUTH_REQUIRED");
	      
	      return AUTH_REQUIRED;
	    }
	}
          
      if (auth_src != sec_login_auth_src_network)
        {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.authenticate: no network credentials for %s", r->connection->user);

          sec_login_purge_context(&login_context, &dce_st);
          ap_note_basic_auth_failure(r);
	  DEBUG_R("auth_dce.authenticate: returning AUTH_REQUIRED");
	  
          return AUTH_REQUIRED;
        }
          

#ifndef NO_CACHING
      DEBUG_R("auth_dce.authenticate: acquiring context pag");
      
      if (server_pag)
	krb5_env[0] = 'X';

      sec_login_set_context(login_context, &dce_st);
      if (dce_st)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.authenticate: sec_login_set_context failed for %s - %s (%d)", r->connection->user, dce_error, dce_st);
	  
	  sec_login_purge_context(&login_context, &dce_st);
	  
	  if (server_pag)
	    {
	      krb5_env[0] = 'K';
	      installpag(server_pag);
	    }
	  
	  ap_note_basic_auth_failure(r);
	  DEBUG_R("auth_dce.authenticate: returning AUTH_REQUIRED");
	  
	  return AUTH_REQUIRED;
	}

      request_config->pag = sec_login_inq_pag(login_context, &dce_st);
      if (dce_st || !request_config->pag)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.authenticate: sec_login_inq_pag failed for %s - %s (%d)", r->connection->user, dce_error, dce_st);
	  
	  sec_login_purge_context(&login_context, &dce_st);
	  
	  if (server_pag)
	    {
	      krb5_env[0] = 'K';
	      installpag(server_pag);
	    }
	  
	  ap_note_basic_auth_failure(r);
	  DEBUG_R("auth_dce.authenticate: returning AUTH_REQUIRED");
	  
	  return AUTH_REQUIRED;
	}

      sec_login_release_context(&login_context, &dce_st);
      if (server_pag)
	{
	  krb5_env[0] = 'K';
	  installpag(server_pag);
	}
      
      auth_dce_add_cached_context(r, request_config);
    }
#else
  request_config->login_context = login_context;
#endif

  if (dir_config->impersonate_browser)
    {

      DEBUG_R("auth_dce.authenticate: impersonating browser");
      
#ifndef NO_CACHING
      krb5_env[0] = 'K';
      sprintf(krb5_env_pag, "%08x", request_config->pag);
      installpag(request_config->pag);
#else

      if (server_context)
	unlink(getenv("KRB5CCNAME")+5);
      
      DEBUG_R("auth_dce.authenticate: calling sec_login_set_context");
      sec_login_set_context(request_config->login_context, &dce_st);
      if (dce_st)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"auth_dce.authenticate: sec_login_set_context failed for %s - %s (%d)", r->connection->user, dce_error, dce_st);
	  
	  sec_login_purge_context(&request_config->login_context, &dce_st);
	  
	  if (server_context)
	    sec_login_set_context(server_context, &dce_st);
	  
	  ap_note_basic_auth_failure(r);
	  DEBUG_R("auth_dce.authenticate: returning AUTH_REQUIRED");
	  
	  return AUTH_REQUIRED;
	}
#endif
    }
                    

  /* The server might have failed to fill in the request_rec
   * structure due to permission errors. If the structure hasn't been
   * filled in, call the function (from http_request.c) again.
   */
  if (r->finfo.st_mode == 0)
    get_path_info(r);
          
  DEBUG_R("auth_dce.authenticate: setting CGI environment variables");

  ap_table_set(r->subprocess_env, "KRB5CCNAME", getenv("KRB5CCNAME"));

  if (dir_config->include_pw)
    ap_table_set(r->subprocess_env, "DCEPW", sent_pw);  

/* requested feature to remove authorization header for requests where
   include_pw not set, currently disabled pending debugging of strange
   side effects

  else
    ap_table_set(r->headers_in, r->proxyreq != STD_PROXY ? "Authorization" : "Proxy-Authorization",
		 ap_pstrcat(r->pool, "Basic ",
                            ap_pbase64encode(r->pool, ap_pstrcat(r->pool, r->connection->user, ":<censored>", NULL)),
                            NULL));
*/
  
  DEBUG_R("auth_dce.authenticate: returning OK");

  return OK;
}


static int authorize(request_rec *r)
{
  dir_config_rec *dir_config = (dir_config_rec *)ap_get_module_config(r->per_dir_config, &auth_dce_module);

  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;

  const char *require_list;
  char *require_type, *entity;
  const array_header *requires_array = ap_requires(r);
  require_line *require_lines;

  int index;

  DEBUG_R("auth_dce.authorize: called for URI %s", r->uri);
  DEBUG_R("auth_dce.authorize: called for filename %s", r->filename);
  
  if (!dir_config->active)
    {
      DEBUG_R("auth_dce.authorize: active not set, returning DECLINED");
      
      return DECLINED;
    }

  if (!ap_get_module_config(r->request_config, &auth_dce_module))
    {
      DEBUG_R("auth_dce.authorize: request_config not set, returning OK");

      return OK;
    }

  DEBUG_R("auth_dce.authorize: called for user %s", r->connection->user);
  
  if (!requires_array)
    {
      /* Assume no require information is the same as "require valid-user" and return OK. */
      DEBUG_R("auth_dce.authorize: no requires line, returning OK");
      
      return OK;
    }

  require_lines = (require_line *)requires_array->elts;
  for(index = 0; index < requires_array->nelts; index++)
    {
      if (!(require_lines[index].method_mask & (1 << r->method_number)))
	continue;

      require_list = require_lines[index].requirement;
      require_type = ap_getword_white(r->pool, &require_list);

      if(!strcmp(require_type, "valid-user"))
	{
	  DEBUG_R("auth_dce.authorize: matched valid-user, returning OK");
	  
	  return OK;
	}

      if(!strcmp(require_type, "user"))
	while(*require_list)
	  {
	    entity = ap_getword_conf(r->pool, &require_list);
	    if(!strcmp(entity, r->connection->user))
	      {
		DEBUG_R("auth_dce.authorize: matched listed user, returning OK");
		
		return OK;
	      }
	  }

      if(!strcmp(require_type, "group"))
	while(*require_list)
	  {
	    entity = ap_getword_conf(r->pool, &require_list);
	    if(sec_rgy_pgo_is_member(sec_rgy_default_handle, sec_rgy_domain_group, (unsigned_char_p_t)entity,
				     (unsigned_char_p_t)r->connection->user, &dce_st))
	      {
		DEBUG_R("auth_dce.authorize: matched listed group %s, returning OK", entity);
		
		return OK;
	      }
	  }
    }

  return ((dir_config->authoritative) ? FORBIDDEN : DECLINED);
}


static int request_cleanup(request_rec *orig)
{
  sec_login_handle_t login_context;
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
    
  request_rec *r = orig;
  dir_config_rec *dir_config;
  request_config_rec *request_config;

  while (r)
    {
      DEBUG_R("auth_dce.request_cleanup: processing URI %s", r->uri);
      DEBUG_R("auth_dce.request_cleanup: processing filename %s", r->filename);
  
      dir_config = (dir_config_rec *)ap_get_module_config(r->per_dir_config, &auth_dce_module);
      
      if (dir_config->active && dir_config->impersonate_browser &&
	  (request_config = (request_config_rec *)ap_get_module_config(r->request_config, &auth_dce_module)))
	{
	  
#ifndef NO_CACHING
	  if (memcmp(request_config->hash_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16))
	    {
	      if (request_config->pag) 
		{
	          DEBUG_R("auth_dce.request_cleanup: releasing cached context");
	          auth_dce_release_cached_context(r, request_config);
		}
	    }
	  else
	    {
	      DEBUG_R("auth_dce.request_cleanup: no cache state in request, purging context");
	      sec_login_context_from_pag(request_config->pag, &login_context, &dce_st);
	      if (dce_st)
		{
		  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
		  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
				"auth_dce.request_cleanup: sec_login_context_from_pag failed - %s (%d)", dce_error, dce_st);
		}
	      else
		sec_login_purge_context(&login_context, &dce_st);
	    }
	  
	  if (server_pag)
	    {
	      sprintf(krb5_env_pag, "%08x", server_pag);
	      installpag(server_pag);
	    }
	  else
	    {
	      krb5_env[0] = 'X';
	      resetpag();
	    }
#else
	  if (request_config->login_context)
	    {
	      DEBUG_R("auth_dce.request_cleanup: purging context");
	      sec_login_purge_context(&request_config->login_context, &dce_st);
	    }
	  
	  if (server_context)
	    {
	      sec_login_set_context(server_context, &dce_st);
	      if (dce_st)
		{
		  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
		  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
				"auth_dce.request_cleanup: sec_login_set_context failed - %s (%d)", dce_error, dce_st);
		}
	    }
#endif
	}
      r = r->next;
    }
  
  return OK;
}

extern uid_t ap_user_id;

static void initialize(server_rec *s, pool *p)
{
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  sec_login_auth_src_t auth_src;
  boolean32 reset_passwd;
  unsigned32 kvno_worked;
  pthread_t refresh_thread;

  DEBUG_S("auth_dce.initialize: user = %s", (auth_dce_server_config.user ? auth_dce_server_config.user : "NULL")); 
  DEBUG_S("auth_dce.initialize: keytab = %s", (auth_dce_server_config.keytab ? auth_dce_server_config.keytab : "NULL")); 
  DEBUG_S("auth_dce.initialize: certify_identity = %d", auth_dce_server_config.certify_identity);
#ifndef NO_CACHING
  DEBUG_S("auth_dce.initialize: cache_buckets = %d", auth_dce_server_config.cache_buckets);
  DEBUG_S("auth_dce.initialize: cache_graceperiod = %d", auth_dce_server_config.cache_graceperiod);
  DEBUG_S("auth_dce.initialize: cache_lifetime = %d", auth_dce_server_config.cache_lifetime);
  DEBUG_S("auth_dce.initialize: cache_max_idle = %d", auth_dce_server_config.cache_max_idle);
  DEBUG_S("auth_dce.initialize: cache_sweep_interval = %d", auth_dce_server_config.cache_sweep_interval);
#endif

  if (auth_dce_server_config.user)
    {
      DEBUG_S("auth_dce.initialize: calling sec_login_setup_identity");

      /* Ensure local credential files have correct ownership */
      DEBUG_S("auth_dce.initialize: calling seteuid(%d)", ap_user_id);
      if (seteuid(ap_user_id) == -1)
	ap_log_error(APLOG_MARK, APLOG_ERR, s, "auth_dce.initialize: seteuid(%d) failed, credential files may be unreadable", ap_user_id);
      
      if (!sec_login_setup_identity((unsigned_char_p_t)auth_dce_server_config.user,
				    sec_login_no_flags, &server_context, &dce_st))
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
		       "auth_dce.initialize: sec_login_setup_identity failed for %s - %s (%d)", auth_dce_server_config.user, dce_error, dce_st);
	  exit(1);
	}

      if (seteuid(0) == -1)
	ap_log_error(APLOG_MARK, APLOG_ERR, s, "auth_dce.initialize: seteuid(0) failed, things will probably be goofy now");

      DEBUG_S("auth_dce.initialize: calling sec_login_valid_from_keytable");
      
      sec_login_valid_from_keytable(server_context, rpc_c_authn_dce_secret, auth_dce_server_config.keytab, (unsigned32) NULL, &kvno_worked,
				    &reset_passwd, &auth_src, &dce_st);
      if (dce_st)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
		       "auth_dce.initialize: sec_login_valid_from_keytable failed for %s - %s (%d)", auth_dce_server_config.user, dce_error, dce_st);
	  sec_login_purge_context(&server_context, &dce_st);
	  exit(1);
	}
      
      if (auth_dce_server_config.certify_identity)
	{
	  DEBUG_S("auth_dce.initialize: calling sec_login_certify_identity");

	  if (!sec_login_certify_identity(server_context, &dce_st))
	    {
	      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
			   "auth_dce.initialize: sec_login_certify_identity failed for %s - %s (%d)", auth_dce_server_config.user, dce_error, dce_st);
	      sec_login_purge_context(&server_context, &dce_st);
	      exit(1);
	    }
	}
	  
      if (auth_src != sec_login_auth_src_network)
	{
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
		       "auth_dce.initialize: no network credentials for %s", auth_dce_server_config.user);
	  sec_login_purge_context(&server_context, &dce_st);
	  exit(1);
	}

      DEBUG_S("auth_dce.initialize: spawning server credential refresh thread");
      
      if (pthread_create(&refresh_thread, pthread_attr_default, refresh_context, (pthread_addr_t) s))
	{
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
		       "auth_dce.initialize: pthread_create failed");
	  exit(1);
	}
	
      pthread_detach(&refresh_thread);
    }

#ifndef NO_CACHING
  DEBUG_S("auth_dce.initialize: calling cache initialization");
  
  auth_dce_initialize_cache(s, p);
#endif
}


static void process_initialize(server_rec *s, pool *p)
{
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;

#ifndef NO_CACHING
  putenv(krb5_env);
  krb5_env[0] = 'X';
#endif
  
  if (server_context)
    {
      DEBUG_S("auth_dce.process_initialize: calling sec_login_set_context");

      sec_login_set_context(server_context, &dce_st);
      if (dce_st)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
		       "auth_dce.process_initialize: sec_login_set_context failed - %s (%d)", dce_error, dce_st);
	  
	  exit(1);
	}
#ifndef NO_CACHING
      server_pag = sec_login_inq_pag(server_context, &dce_st);
      if (dce_st)
	{
	  dce_error_inq_text(dce_st, dce_error, &dce_error_st);
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, s,
		       "auth_dce.process_initialize: sec_login_inq_pag failed - %s (%d)", dce_error, dce_st);
	  
	  exit(1);
	}

      sec_login_release_context(&server_context, &dce_st);

      krb5_env[0] = 'K';
      sprintf(krb5_env_pag, "%08x", server_pag);
      installpag(server_pag);		   
#endif
    }

#ifdef CACHE_TEST_LEVEL
  srand48(getpid() ^ time(NULL));
#endif
}


module auth_dce_module = {
   STANDARD_MODULE_STUFF,
   initialize,	        	/* initializer */
   create_dir_config,    	/* dir config creater */
   merge_dir_configs,   	/* dir merger --- default is to override */
   create_server_config,	/* server config */
   merge_server_configs,	/* merge server config */
   cmds,		        /* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   authenticate,	        /* check_user_id */
   authorize,	                /* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   request_cleanup,		/* logger */
   NULL,                        /* [3] header parser */
   process_initialize,          /* process initializer */
   NULL,                        /* process exit/cleanup */
   NULL                         /* [1] post read_request handling */
};
