#ifndef MOD_SSL_PREAUTH_H
#define MOD_SSL_PREAUTH_H

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_ldap.h>
#include <util_ldap.h>

#include <mod_ssl.h>

#define FILTER_LENGTH MAX_STRING_LEN

typedef struct {
    int ssl_preauth_enabled;
    char *ldap_remote_user_attr;
/* LDAP related settings: */
    char *ldap_url;
    char *ldap_host;
    int port;
    char *binddn;
    char *bindpw;
    char *basedn;
    char *attribute;
    char **attributes;
    int scope;
    char *filter;
    int secure;
} ssl_preauth_config;

const char *
ssl_preauth_ldap_parse_url(cmd_parms *cmd,
                           void *config,
                           const char *url,
                           const char *mode);

void
ssl_preauth_ldap_build_filter(char *filtbuf,
                              request_rec *r,                              
                              const char* sent_user,
                              const char* sent_filter,
                              ssl_preauth_config *sec);

#define command(name, func, var, type, usage)		\
    AP_INIT_ ## type (name, (void*) func,		\
	(void*)APR_OFFSETOF(ssl_preauth_config, var),	\
	OR_AUTHCFG | RSRC_CONF, usage)

#endif
