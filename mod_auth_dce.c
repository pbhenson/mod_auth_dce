/*
 * DCE Authentication Module for Apache HTTP Server
 *
 * Paul Henson
 *
 * Copyright (c) Paul Henson -- see LICENSE file for details
 *
 * This module is designed to allow authentication and authorization based
 * on DCE credentials.
 *
 * DCE authentication can be turned on and off on a per directory basis.
 * When DCE authentication is enabled, the function  check_dce_access()
 * is called during the initial processing of a request to check whether
 * privileges are needed to complete the request. If the server is able
 * to process the request without credentials, the module declines and the
 * request proceeds normally. If credentials are required, check_dce_access()
 * checks whether the browser supplied an Authorization header; if so,
 * the request procedes, otherwise, AUTH_REQUIRED is returned.
 *  
 * The function authenticate_dce_user() verifies the username/password
 * provided and obtains DCE credentials for the user. If credentials are
 * not required, this function declines, even if an Authorization header
 * was provided. If credentials are required, this function calls the
 * necessary DCE security routines to obtain them. If the user does not
 * exist, or the password is incorrect, the function returns AUTH_REQUIRED.
 * If all goes well, the function applies the obtained credentials to the
 * current process. It also saves a pointer to the credentials so they
 * can be purged at a later stage. If necessary, it calls the Apache
 * function get_path_info(), which might have failed in an earlier stage
 * due to permission errors. Finally, it sets two environment variables
 * for DCE authenticated CGI processes: KRB5CCNAME, which is necessary
 * to pass DCE credentials to the CGI, and DCEPW, for CGIs that need the
 * user's password to function. The user's name is already passed in the
 * standard CGI REMOTE_USER environment variable.
 *
 * The final function in this module, dce_log_transaction(), purges any
 * DCE credentials that were obtained during the course of the request.
 *
 * This module currently requires patching two Apache source files for
 * correct operation:
 *
 *   mod_cgi.c - The call to can_exec(), which checks execute
 *               permissions by comparing the server's UID and GID to
 *               owner/group permissions on the file, does not work
 *               correctly when a CGI might not be executable by the
 *               server user. This call needs to be replaced with a call
 *               to the access() system routine instead.
 *
 *   http_request.c - When a request structure is being built, a
 *                    function named directory_walk() in this source file
 *                    is called to accomplish three things. First, it calls
 *                    get_path_info(), also in this source file, to separate
 *                    the PATH_INFO information in the URI from the
 *                    filename listing the file being requested. Secondly,
 *                    it checks for symlinks if they are not allowed.
 *                    Finally, it looks for .htaccess files if any
 *                    AllowOverride is enabled.
 *
 *                    Checking for symlinks and .htaccess files will not
 *                    work reliably with this module, because the checks
 *                    are made before credentials are obtained, and the
 *                    server might not be able to read the directories.
 *                    It is recommended that symlinks be enabled and
 *                    .htaccess files be disabled in any directory
 *                    heirarchy in which DCE authentication is enabled.
 *
 *                    The get_path_info() routine calls stat() as it
 *                    tries to separate the PATH_INFO information. If the
 *                    stat() fails, it assumes the file in question must
 *                    not exist. This routine must be modified to check for
 *                    a permission error in the call to stat(). If a
 *                    permission error is detected, the routine should
 *                    immediately return, and will be called again from
 *                    authenticate_dce_user() once credentials have been
 *                    obtained.
 *
 *
 * Due to a bug in DCE, the process still has inappropriate access to
 * DFS filesystems after the credentials are purged. Currently, the only
 * workaround for this bug is to set "MaxRequestsPerChild 2" in the
 * httpd.conf file. (Intuitively, you would set the value to 1. However,
 * with Apache's current implementation of that configuration directive,
 * a value of 1 would allow the child to service no requests). This
 * introduces considerable overhead, but prevents unauthorized access.
 * Hopefully, this bug in DCE will be fixed soon.
 *
 * As of DEC DCE 2.0, the aforementioned bug seems to be fixed.
 *
 */


/* We're still debugging... */
#define DEBUG

/* Production mode */
/* #undef DEBUG */


/* Define debugging log code */
#ifdef DEBUG
#define log_debug(X, Y) log_error(X, Y)
#else
#define log_debug(X, Y)
#endif


/* Include file to access DCE security API */
#include <dce/sec_login.h>


/* Include files to access Apache module API */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"


/* Define module structure for per-directory configuration.
 * The structure has only one member, which determines whether DCE
 * authentication is turned on in a given directory.
 */
typedef struct auth_dce_config_struct {
          int do_auth_dce;
} auth_dce_config_rec;


/* Function to create and return an empty per-directory module
 * configuration structure.
 */
void *create_auth_dce_dir_config (pool *p, char *d)
{
    return pcalloc (p, sizeof(auth_dce_config_rec));
}


/* Function that is called to configure a directory when an AuthDCE
 * configuration directive is found.
 * It is passed a flag indicating whether DCE authentication should
 * be enabled in this directory.
 */
char *set_auth_dce (cmd_parms *cmd, void *dv, int arg) {
  auth_dce_config_rec *d = (auth_dce_config_rec *)dv;
  
  d->do_auth_dce = arg;
  
  return NULL;
}


/* This structure defines the configuration commands this module
 * is willing to handle.
 * Currently, the only configuration command available is "AuthDCE",
 * which turns on/off DCE authentication in a directory.
 */
command_rec auth_dce_cmds[] = {
{ "AuthDCE", set_auth_dce, NULL, OR_AUTHCFG, FLAG,
  "Perform DCE authentication in this directory?" },
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

  /* What type of credentials were obtained */
  sec_login_auth_src_t auth_src;

  /* Structure passed to DCE to verify user's password */
  sec_passwd_rec_t pw_entry;

  sec_passwd_str_t dce_pw;

  /* Whether or not the password has expired */
  boolean32 reset_passwd;

  
  /* Obtain the per-directory configuration for this request */
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    get_module_config (r->per_dir_config, &auth_dce_module);

  
  log_debug(pstrcat(r->pool,
                    "authenticate_dce_user: called for URI ",
                    r->uri,
                    NULL),
            r->server);
  log_debug(pstrcat(r->pool,
                    "authenticate_dce_user: called for filename ",
                    r->filename,
                    NULL),
            r->server);


  /* Is DCE authentication turned on for this request? If not, decline it */
  if (!a->do_auth_dce)
    {
      log_debug("authenticate_dce_user: do_auth_dce not set, returning DECLINED",
                r->server);
      return DECLINED;
    }

  
  /* If check_dce_access() didn't set the request_config variable, we don't
   * need credentials to complete the request. Return OK without bothering
   * with DCE calls
   */
  if (!get_module_config(r->request_config, &auth_dce_module))
    {
      log_debug("authenticate_dce_user: request_config not set, returning OK",
                r->server);
      return OK;
    }

  
  /* dce_log_transaction() checks the request_config variable when it tries
   * to purge the DCE context. Set it to NULL initially.
   */
  set_module_config(r->request_config, &auth_dce_module, NULL);

  
  /* Call Apache function to extract the username and password information
   * from the request.
   */
  get_basic_auth_pw (r, &sent_pw);

  log_debug(pstrcat(r->pool,
                    "authenticate_dce_user: User = ",
                    r->connection->user,
                    " PW = ",
                    "<not shown>" /* sent_pw */ ,
                    NULL),
            r->server);
  log_debug("authenticate_dce_user: calling sec_login_setup_identity", r->server);

  
  /* sec_login_setup_identity() verifies that the username given is
   * correct and does the initial setup of the login context.
   */
  if (sec_login_setup_identity(r->connection->user, sec_login_no_flags,
                               &login_context, &dce_st))
    {
      /* Now that the username has been verified, set up the structure
       * to validate the password.
       */
      pw_entry.version_number = sec_passwd_c_version_none;
      pw_entry.pepper = NULL;
      pw_entry.key.key_type = sec_passwd_plain;

      strncpy( (char *)dce_pw, sent_pw, sec_passwd_str_max_len);
      dce_pw[sec_passwd_str_max_len] = ' ';
      pw_entry.key.tagged_union.plain = &(dce_pw[0]);

      log_debug("authenticate_dce_user: calling sec_login_validate_identity",
                r->server);

      
      /* sec_login_validate_identity() verifies that the correct password has
       * been furnished and completes the setup of the login context. It also
       * returns whether the user's password has expired, and what source
       * supplied the authorization.
       */
      if (sec_login_validate_identity(login_context, &pw_entry, &reset_passwd,
                                      &auth_src, &dce_st))
        {
          log_debug("authenticate_dce_user: calling sec_login_certify_identity", r->server);

          /* sec_login_certify_identity() ensures that the correct security
           * server validated the password.
           */
          if (!sec_login_certify_identity(login_context, &dce_st))
            {
              char dce_st_buf[15];
              sprintf(dce_st_buf, "%d", dce_st);

              log_debug(pstrcat(r->pool,
                                "authenticate_dce_user: certify_identity failed, dce_st = ",
                                dce_st_buf,
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
              log_debug("authenticate_dce_user: no network credentials",
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

          
          /* Technically, to meet DCE login standards, we should check whether
           * the user's password has expired and whether or not their account
           * has expired. Nah, let's not bother. Here's an approximation of
           * the code you'd need, though:
           *
           *   if (reset_passwd)
           *     do_something_about_expired_password;
           *
           *   sec_login_get_pwent(login_context, &pw_entry, &dce_st);
           *   if (pw_entry.pw_expire < todays_date())
           *     do_something_about_expired_account
           */

          log_debug("authenticate_dce_user: calling sec_login_set_context",
                    r->server);

          
          /* Assign the new login context to the current process */
          sec_login_set_context(login_context, &dce_st);

          
          /* Save the address of the login context so dce_log_transaction
           * can purge it later.
           */
          set_module_config(r->request_config, &auth_dce_module, login_context);
                    

          /* The server might have failed to fill in the request_rec
           * structure due to permission errors. If the structure hasn't been
           * filled in, call the function (from http_request.c) again.
           */
          if (r->finfo.st_mode == 0)
            get_path_info(r);
          
          
          log_debug("authenticate_dce_user: setting CGI environment variables",
                    r->server);

          
          /* Set two environment variables for running CGIs. The first is
           * so the CGI can find its credentials, the second is for DCE
           * operations that require the user's password. We could check
           * and only set these if the request involves a CGI, but that would
           * be at least as much overhead as just setting them.
           */
          table_set(r->subprocess_env, "KRB5CCNAME", getenv("KRB5CCNAME"));
          table_set(r->subprocess_env, "DCEPW", sent_pw);  

          log_debug("authenticate_dce_user: returning OK",
                    r->server);


          /* Whee! */
          return OK;
        }
      else
        {
          /* Wrong password. Clean up and return */
          char dce_st_buf[15];
          sprintf(dce_st_buf, "%d", dce_st);

          log_debug(pstrcat(r->pool,
                            "authenticate_dce_user: sec_login_validate_ident failed, dce_st =  ",
                            dce_st_buf,
                            NULL),
                    r->server);
          
          sec_login_purge_context(&login_context, &dce_st);
          note_basic_auth_failure(r);
          log_debug("authenticate_dce_user: returning AUTH_REQUIRED",
                    r->server);
          return AUTH_REQUIRED;
        }
    }
  else
    {
      /* Invalid username. Clean up and return */
      char dce_st_buf[15];
      sprintf(dce_st_buf, "%d", dce_st);
      log_debug(pstrcat(r->pool,
                        "authenticate_dce_user: sec_login_setup_identity failed, dce_st = ",
                        dce_st_buf,
                        NULL),
                r->server);
      
      sec_login_purge_context(&login_context, &dce_st);
      note_basic_auth_failure(r);
      
      log_debug("authenticate_dce_user: returning AUTH_REQUIRED",
                r->server);
      return AUTH_REQUIRED;
    }
}

/* Function to return OK for the group check if DCE authentication is
 * turned on
 */
int fake_dce_group_check (request_rec *r)
{
  /* Obtain the per-directory configuration for this request */  
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    get_module_config (r->per_dir_config, &auth_dce_module);

  
  log_debug(pstrcat(r->pool,
                    "fake_dce_group_check: called for URI ",
                    r->uri,
                    NULL),
            r->server);
    log_debug(pstrcat(r->pool,
                    "fake_dce_group_check: called for filename ",
                    r->filename,
                    NULL),
            r->server);


  /* Is DCE authentication turned on for this request? If so, return OK.
   * if not, decline it */
  if (a->do_auth_dce)
    {
      log_debug("check_dce_access: do_auth_dce set, returning OK",
                r->server);
      return OK;
    }
  else
    {
      log_debug("check_dce_access: do_auth_dce not set, returning DECLINED",
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

  /* Variable DCE functions return status in */
  error_status_t dce_st;

  
  /* Obtain the per-directory configuration for this request */  
  auth_dce_config_rec *a = (auth_dce_config_rec *)
    get_module_config (r->per_dir_config, &auth_dce_module);

  
  log_debug(pstrcat(r->pool,
                    "check_dce_access: called for URI ",
                    r->uri,
                    NULL),
            r->server);
    log_debug(pstrcat(r->pool,
                    "check_dce_access: called for filename ",
                    r->filename,
                    NULL),
            r->server);


  /* Is DCE authentication turned on for this request? If not, decline it */
  if (!a->do_auth_dce)
    {
      log_debug("check_dce_access: do_auth_dce not set, returning DECLINED",
                r->server);
      return DECLINED;
    }

  
  /* Check whether we can get to the file. First we stat() it, then we check
   * for the correct permissions for the type of request. If anything fails
   * due to permission errors, the file is not accessible. If we get any
   * other type of error, just say the file is accessible and let the
   * server handle it.
   */
  if(stat(r->filename, &statbuf))
    accessible = (errno != EACCES);
  else if (S_ISDIR(statbuf.st_mode))
    {
      if (access(r->filename, R_OK | X_OK))
        accessible = (errno != EACCES);
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

      log_debug("check_dce_access: file is accessible, returning OK",
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
          log_debug("check_dce_access: file not accessible, Authorization given, returning OK",
                    r->server);
          set_module_config(r->request_config, &auth_dce_module, (void *)1);
          return OK;
        }
      else
        {
          /* No Authorization header. Tell the browser it needs to send
           * authorization information.
           */
          log_debug("check_dce_access: file not accessible, returning AUTH_REQUIRED",
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

  log_debug("dce_log_transaction: called", orig->server);


  /* A module log function is unique in that it doesn't get passed a single
   * request_rec structure, but rather a linked list. The original request
   * might have resulted in any number of internal redirects, so each
   * request_rec structure must be examined.
   */
  while(r)
    {
      log_debug(pstrcat(r->pool,
                        "dce_log_transaction: processing URI ",
                        r->uri,
                        NULL),
                r->server);

      log_debug(pstrcat(r->pool,
                        "dce_log_transaction: processing filename ",
                        r->filename,
                        NULL),
                r->server);

      /* Get the per-directory configuration information for this request */
      a = (auth_dce_config_rec *)
        get_module_config (r->per_dir_config, &auth_dce_module);

      
      /* If DCE authentication is turned on for this request, check if
       * there is any context to purge. If so, purge it.
       */
      if (a->do_auth_dce)
        if ((login_context = (sec_login_handle_t)
             get_module_config(r->request_config, &auth_dce_module)))
          {
            log_debug("dce_log_transaction: purging a DCE login context",
                      r->server);
            sec_login_purge_context(&login_context, &dce_st);
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
   NULL,			/* dir merger --- default is to override */
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
