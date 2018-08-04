#include <stdio.h>
#include <errno.h>
#include <dce/sec_login.h>
#include <dce/dce_error.h>

#ifdef AIX
#define afs_syscall kafs_syscall
#endif

#define AFSCALL_RESETPAG 20     /* reset PAG syscall */

int access_file();
void acquire_creds(sec_login_handle_t *context);
void export(sec_login_handle_t *context);
void import(sec_login_handle_t *context);
void purge(sec_login_handle_t *context);

int main()
{
  sec_login_handle_t context;

  if (access_file())
    {
      printf("test: file is accessible before acquiring context\n");
      printf("      Please fix file permissions and run test again\n");
      exit(1);
    }
  
  acquire_creds(&context);
  
  if (!access_file())
    {
      printf("test: file is not accessible after acquiring context\n");
      printf("      Please fix file permissions and run test again\n");
      exit(1);
    }
  
  export(&context);

  if (access_file())
    {
      printf("test: file is still accessible after releasing context\n");
      printf("      Caching will not work securely and should be turned off\n");
    }

  import(&context);
  
  if (!access_file())
    {
      printf("test: file is not accessible after importing context\n");
      printf("      Caching will not work securely and should be turned off\n");
    }
  
  purge(&context);

  if (access_file())
    {
      printf("test: file is still accessible after purging context\n");
      printf("      mod_auth_dce will not work securely if more than one\n");
      printf("      request is served by each server\n");
      exit(1);
    }

  exit(0);
}

int access_file()
{
  FILE *fp;
  
  if (fp = fopen(FILENAME, "r"))
    {
      fclose(fp);
      return 1;
    }

  if (errno == EACCES)
    return 0;

  perror("test: unexpected error accessing file");

  exit(1);
}


void acquire_creds(sec_login_handle_t *context)
{
  error_status_t dce_st;
  sec_login_auth_src_t auth_src;
  sec_passwd_rec_t pw_entry;
  boolean32 reset_passwd;
  sec_passwd_str_t tmp_pw;
  dce_error_string_t dce_error;
  int dce_error_st;

  if (!sec_login_setup_identity(USERNAME, sec_login_no_flags, context, &dce_st))
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: Unable to set up identity - %s\n", dce_error);
      exit(1);
    }
  
  pw_entry.version_number = sec_passwd_c_version_none;
  pw_entry.pepper = NULL;
  pw_entry.key.key_type = sec_passwd_plain;
  strncpy( (char *) tmp_pw, (char *) USERPASS, sec_passwd_str_max_len);
  tmp_pw[sec_passwd_str_max_len] = ' ';
  pw_entry.key.tagged_union.plain = &(tmp_pw[0]);
  
  if (!sec_login_validate_identity(*context, &pw_entry, &reset_passwd, &auth_src, &dce_st))
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: Unable to validate identity - %s\n", dce_error);
      exit(1);
    }

  if (auth_src != sec_login_auth_src_network)
    {
      printf("test: Authentication did not yield network credentials");
      exit(1);
    }

  if (!sec_login_certify_identity(*context, &dce_st))
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: Unable to certify identity - %s\n", dce_error);
      exit(1);
    }
  
  sec_login_set_context(*context, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: error setting context - %s\n", dce_error);
      exit(1);
    }

}


unsigned32 cbuf_len = 2048;
idl_byte cbuf[2048];
unsigned32 len_used, len_needed;

void export(sec_login_handle_t *context)
{
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;

  sec_login_export_context(*context, cbuf_len, cbuf, &len_used, &len_needed, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: error exporting context - %s\n", dce_error);
      exit(1);
    }

  sec_login_release_context(context, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: error releasing context - %s\n", dce_error);
      exit(1);
    }

  afs_syscall(AFSCALL_RESETPAG);
}

void import(sec_login_handle_t *context)
{
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;

  sec_login_import_context(cbuf_len, cbuf, context, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: error importing context - %s\n", dce_error);
      exit(1);
    }

  sec_login_set_context(*context, &dce_st);
    if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: error setting imported context - %s\n", dce_error);
      exit(1);
    }

}

void purge(sec_login_handle_t *context)
{
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;

  sec_login_purge_context(context, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      printf("test: error purging context - %s\n", dce_error);
      exit(1);
    }
}

