#include "mod_ssl_preauth.h"

module AP_MODULE_DECLARE_DATA ssl_preauth_module;

/* In order to get information from mod_ssl we need to check some its variables
 * that are not yet propagated into the Apache environment space. Therefore,
 * we'll use the internall call of mod_ssl to access the variables set */
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) * preauth_ssl_var_lookup;

static APR_OPTIONAL_FN_TYPE(uldap_connection_close) *util_ldap_connection_close;
static APR_OPTIONAL_FN_TYPE(uldap_connection_find) *util_ldap_connection_find;
static APR_OPTIONAL_FN_TYPE(uldap_cache_getuserdn) *util_ldap_cache_getuserdn;

static void
log_rerror(const char *file, int line, int module_index, int level, int status,
           const request_rec *r, const char *fmt, ...)
{
    char errstr[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(errstr, sizeof(errstr), fmt, ap);
    va_end(ap);

    ap_log_rerror(file, line, module_index, level | APLOG_NOERRNO, status, r, "%s", errstr);
}

static void *
create_dir_config(apr_pool_t *p, char *d)
{
    ssl_preauth_config *conf;

    conf = (ssl_preauth_config *) apr_pcalloc(p, sizeof(*conf));

    return conf;
}

static apr_status_t
authnz_ldap_cleanup_connection_close(void *param)
{
    util_ldap_connection_t *ldc = param;
    util_ldap_connection_close(ldc);
    return APR_SUCCESS;
}

#define AUTHN_PREFIX "AUTHENTICATE_"
static int
lookup_ldap_user(request_rec *r, const char * ssl_client_dn, char **user)
{
    util_ldap_connection_t *ldc = NULL;
    int ret;
    char filtbuf[FILTER_LENGTH];
    const char *dn = NULL;
    const char **vals = NULL;
    ssl_preauth_config *conf = (ssl_preauth_config *) ap_get_module_config(r->per_dir_config,
                                                                           &ssl_preauth_module);

    if (util_ldap_connection_close == NULL || util_ldap_connection_find == NULL ||
        util_ldap_cache_getuserdn == NULL) {
	log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	           "Module mod_ldap not loaded but required by the configuration of the mod_ssl_preauth module.");
	return DECLINED;
    }

    *user = NULL;

    if (conf->ldap_host == NULL) {
       log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No host given");
       return DECLINED;
    }

    ldc = util_ldap_connection_find(r, conf->ldap_host, conf->port,
				    NULL, NULL, always,
				    conf->secure);
    if (ldc == NULL) {
	log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		   "Failed to allocate LDAP connection, probably running out of memory");
	return DECLINED;
    }

    apr_pool_cleanup_register(r->pool, ldc,
			      authnz_ldap_cleanup_connection_close,
			      apr_pool_cleanup_null);

    ssl_preauth_ldap_build_filter(filtbuf, r, ssl_client_dn, NULL, conf);

    /* XXX can be cached, see authn_ldap_request_t. Not sure if it makes sense, though */
    ret = util_ldap_cache_getuserdn(r, ldc, conf->ldap_url, conf->basedn,
			conf->scope, conf->attributes, filtbuf, &dn, &vals);
    if (ret != LDAP_SUCCESS) {
        log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to retrieve user DN. %s: %s",
                   ldc->reason, ldap_err2string(ret));
        return DECLINED;
    }

    /* add attributes to the environment */
    if (conf->attributes && vals) {
	apr_table_t *e = r->subprocess_env;
	int i = 0;
	while (conf->attributes[i]) {
	    char *name = apr_pstrcat(r->pool, AUTHN_PREFIX, conf->attributes[i], NULL);
	    char *p;

	    p = name + strlen(AUTHN_PREFIX);
	    while (p && *p) {
		*p = apr_toupper(*p);
		p++;
	    }
	    apr_table_setn(e, name, vals[i]);
	    
	    if (conf->ldap_remote_user_attr &&
		!strcmp(conf->ldap_remote_user_attr, conf->attributes[i]))
		*user = apr_pstrdup(r->pool, vals[i]);
	    i++;
	}
    }

    if (conf->ldap_remote_user_attr && *user == NULL) {
	log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
		  "REMOTE_USER was to be set with attribute '%s', "
                  "but this attribute was not requested for in the "
                  "LDAP query for the user.", conf->ldap_remote_user_attr);
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    return 0;
}

static int
ssl_preauth_authn(request_rec *r)
{
    const char *ssl_client_verify = NULL;
    const char *ssl_client_dn = NULL;
    char *user = NULL;
    int ret;
    ssl_preauth_config *conf = (ssl_preauth_config *) ap_get_module_config(r->per_dir_config,
									   &ssl_preauth_module);

    log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r, "Entering SSL preauthentication module");

    if (!conf->ssl_preauth_enabled)
	return DECLINED;

    if (preauth_ssl_var_lookup == NULL) {
	log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_ssl does not expose calls needed (ssl_var_lookup())");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    ssl_client_verify = preauth_ssl_var_lookup(r->pool, r->server,
				               r->connection, r, "SSL_CLIENT_VERIFY");
    if (ssl_client_verify == NULL || strcmp(ssl_client_verify, "SUCCESS") != 0)
	return DECLINED;

    ssl_client_dn = preauth_ssl_var_lookup(r->pool, r->server,
				           r->connection, r, "SSL_CLIENT_S_DN");
    if (ssl_client_dn == NULL)
	return DECLINED;

    user = apr_pstrdup(r->pool, ssl_client_dn);
    if (conf->ldap_url) {
        ret = lookup_ldap_user(r, ssl_client_dn, &user);
        if (ret)
	    return DECLINED;
    }

    r->user = apr_pstrdup(r->pool, user);
    r->ap_auth_type = apr_pstrdup(r->pool, "SSL");

    log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r, "Exiting SSL preauthentication module");

    return OK;
}

static int
ssl_preauth_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    if (ap_find_linked_module("mod_ssl.c") == NULL) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
		     "Required module mod_ssl is missing. mod_ssl_preauth cannot work without it");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

static void
ssl_preauth_fn_retrieve(void)
{
    util_ldap_connection_close  = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_close);
    util_ldap_connection_find   = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_find);
    util_ldap_cache_getuserdn   = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_getuserdn);
    preauth_ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
}

static void
register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(ssl_preauth_authn, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(ssl_preauth_post_config,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_optional_fn_retrieve(ssl_preauth_fn_retrieve, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ssl_preauth_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    NULL,
    NULL,
    NULL,
    ssl_preauth_cmds,
    register_hooks
};
