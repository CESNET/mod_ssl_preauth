/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* The following routines are taken from mod_authnz_ldap.c from the Apache
   sources, using the license above */

#include "mod_ssl_preauth.h"

/*
 * Use the ldap url parsing routines to break up the ldap url into
 * host and port.
 */
const char *
ssl_preauth_ldap_parse_url(cmd_parms *cmd,
                           void *config,
                           const char *url,
                           const char *mode)
{
    int rc;
    apr_ldap_url_desc_t *urld;
    apr_ldap_err_t *result;

    ssl_preauth_config *sec = config;

    rc = apr_ldap_url_parse(cmd->pool, url, &(urld), &(result));
    if (rc != APR_SUCCESS) {
        return result->reason;
    }

    /* Set all the values, or at least some sane defaults */
    if (sec->ldap_host) {
        char *p = apr_palloc(cmd->pool, strlen(sec->ldap_host) + strlen(urld->lud_host) + 2);
        strcpy(p, urld->lud_host);
        strcat(p, " ");
        strcat(p, sec->ldap_host);
        sec->ldap_host = p;
    }
    else {
        sec->ldap_host = urld->lud_host? apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
    }
    sec->basedn = urld->lud_dn? apr_pstrdup(cmd->pool, urld->lud_dn) : "";
    if (urld->lud_attrs && urld->lud_attrs[0]) {
        int i = 1;
        while (urld->lud_attrs[i]) {
            i++;
        }
	sec->attributes = apr_pcalloc(cmd->pool, sizeof(char *) * (i+1));
	i = 0;
	while (urld->lud_attrs[i]) {
	    sec->attributes[i] = apr_pstrdup(cmd->pool, urld->lud_attrs[i]);
	    i++;
	}
	sec->attribute = sec->attributes[0];
    }
    else {
        sec->attribute = "uid";
    }

    sec->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ?
        LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

    if (urld->lud_filter) {
        if (urld->lud_filter[0] == '(') {
            /*
             * Get rid of the surrounding parens; later on when generating the
             * filter, they'll be put back.
             */
            sec->filter = apr_pstrdup(cmd->pool, urld->lud_filter+1);
            sec->filter[strlen(sec->filter)-1] = '\0';
        }
        else {
            sec->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
        }
    }
    else {
        sec->filter = "objectclass=*";
    }

    if (mode) {
        if (0 == strcasecmp("NONE", mode)) {
            sec->secure = APR_LDAP_NONE;
        }
        else if (0 == strcasecmp("SSL", mode)) {
            sec->secure = APR_LDAP_SSL;
        }
        else if (0 == strcasecmp("TLS", mode) || 0 == strcasecmp("STARTTLS", mode)) {
            sec->secure = APR_LDAP_STARTTLS;
        }
        else {
            return "Invalid LDAP connection mode setting: must be one of NONE, "
                   "SSL, or TLS/STARTTLS";
        }
    }

      /* "ldaps" indicates secure ldap connections desired
      */
    if (strncasecmp(url, "ldaps", 5) == 0)
    {
        sec->secure = APR_LDAP_SSL;
        sec->port = urld->lud_port? urld->lud_port : LDAPS_PORT;
    }
    else
    {
        sec->port = urld->lud_port? urld->lud_port : LDAP_PORT;
    }

    sec->ldap_url = apr_pstrdup(cmd->pool, url);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                 cmd->server, "auth_ldap url parse: `%s', Host: %s, Port: %d, DN: %s, attrib: %s, scope: %s, filter: %s, connection mode: %s",
                 url,
                 urld->lud_host,
                 urld->lud_port,
                 urld->lud_dn,
                 urld->lud_attrs? urld->lud_attrs[0] : "(null)",
                 (urld->lud_scope == LDAP_SCOPE_SUBTREE? "subtree" :
                  urld->lud_scope == LDAP_SCOPE_BASE? "base" :
                  urld->lud_scope == LDAP_SCOPE_ONELEVEL? "onelevel" : "unknown"),
                 urld->lud_filter,
                 sec->secure == APR_LDAP_SSL  ? "using SSL": "not using SSL"
                 );

    return NULL;
}

void
ssl_preauth_ldap_build_filter(char *filtbuf,
                              request_rec *r,
                              const char* sent_user,
                              const char* sent_filter,
                              ssl_preauth_config *sec)
{
    char *p, *q, *filtbuf_end;
    char *user, *filter;

    if (sent_user != NULL) {
        user = apr_pstrdup (r->pool, sent_user);
    }
    else
        return;

    if (sent_filter != NULL) {
        filter = apr_pstrdup (r->pool, sent_filter);
    }
    else
        filter = sec->filter;

    /*
     * Create the first part of the filter, which consists of the
     * config-supplied portions.
     */
    apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(%s=", filter, sec->attribute);

    /*
     * Now add the client-supplied username to the filter, ensuring that any
     * LDAP filter metachars are escaped.
     */
    filtbuf_end = filtbuf + FILTER_LENGTH - 1;
#if APR_HAS_MICROSOFT_LDAPSDK
    for (p = user, q=filtbuf + strlen(filtbuf);
         *p && q < filtbuf_end; ) {
        if (strchr("*()\\", *p) != NULL) {
            if ( q + 3 >= filtbuf_end)
              break;  /* Don't write part of escape sequence if we can't write all of it */
            *q++ = '\\';
            switch ( *p++ )
            {
              case '*':
                *q++ = '2';
                *q++ = 'a';
                break;
              case '(':
                *q++ = '2';
                *q++ = '8';
                break;
              case ')':
                *q++ = '2';
                *q++ = '9';
                break;
              case '\\':
                *q++ = '5';
                *q++ = 'c';
                break;
                        }
        }
        else
            *q++ = *p++;
    }
#else
    for (p = user, q=filtbuf + strlen(filtbuf);
         *p && q < filtbuf_end; *q++ = *p++) {
        if (strchr("*()\\", *p) != NULL) {
            *q++ = '\\';
            if (q >= filtbuf_end) {
              break;
            }
        }
    }
#endif
    *q = '\0';

    /*
     * Append the closing parens of the filter, unless doing so would
     * overrun the buffer.
     */
    if (q + 2 <= filtbuf_end)
        strcat(filtbuf, "))");
}
