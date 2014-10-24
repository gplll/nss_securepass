/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014
 *  
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <pthread.h>
#include <syslog.h>
#include <netdb.h>
#include <nss.h>
#include <errno.h>
#include <pwd.h>
#include <curl/curl.h>
#include "jsmn.h"
#include "sp_api.h"
#include "nss_sp.h"

#define SP_INIT \
	if ((sp_config.status != SP_INITED)) { \
        if (!(sp_init ())) return NSS_STATUS_UNAVAIL; \
   	}

static pthread_mutex_t sp_lock = PTHREAD_MUTEX_INITIALIZER;
static int get_user_list = 0;
static char **user_list = NULL; /* pointer to cached user list */
static int u_len = 0;	/* number of users in cached user list */
static int u_idx; 	/* Index of next user to be read into list */

void _nss_sp_enter (void) {
	NSS_SP_LOCK (sp_lock);
}

void _nss_sp_leave (void) {
	NSS_SP_UNLOCK (sp_lock);
}

enum nss_status _nss_sp_setpwent (void) {

	SP_INIT;
	debug (2, "==> _nss_sp_setpwent");
	_nss_sp_enter ();
	get_user_list = 1;
	_nss_sp_leave ();
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sp_endpwent (void) {
	SP_INIT;
	debug (2, "==> _nss_sp_endpwent");
	_nss_sp_enter ();
	get_user_list = 1;
	_nss_sp_leave ();
	return NSS_STATUS_SUCCESS;
}


enum nss_status _nss_sp_getpwnam_r (const char *name,
              struct passwd *result,
              char *buffer, size_t buflen, int *errnop) {

	sp_xattrs_t *xattrs;

	SP_INIT;
	debug (2, "==> _nss_sp_getpwnam_r name=%s", name);

	/* hack to avoid bash completion issue */
	if (strcmp (name, "*") == 0) {
		return NSS_STATUS_NOTFOUND;
	}

	/* call SP API */
	int rc = sp_xattrs_p (&xattrs, name, 1);
	if (rc == -1) {
		debug (1, "sp_xattrs() returned error");
		return NSS_STATUS_NOTFOUND;
	} else {
		int nlen = strlen (name);

		/* check buffer space */
		if ((nlen + 5) > buflen) {
			*errnop = ERANGE;
			free (xattrs);
			return NSS_STATUS_TRYAGAIN;
		}

		/* Fill the output fields */
		int pos = 0;

		result->pw_uid = strtoul(xattrs->posixuid, NULL, 10);

		result->pw_gid = strtoul(xattrs->posixgid, NULL, 10);

		result->pw_name = buffer;
		strcpy (buffer, name);
		pos += strlen (name) + 1;

		result->pw_passwd = buffer + pos;
	    buffer[pos] = 0;	
		pos++;

		result->pw_gecos = buffer + pos;
		strcpy (result->pw_gecos, xattrs->posixgecos);
		pos += strlen (result->pw_gecos) + 1;

		result->pw_dir = buffer + pos;
		strcpy (result->pw_dir, xattrs->posixhomedir);
		pos += strlen (result->pw_dir) + 1;

		result->pw_shell = buffer + pos;
		strcpy (result->pw_shell, xattrs->posixshell);
		pos += strlen (result->pw_shell) + 1;

		free (xattrs);
		return NSS_STATUS_SUCCESS;
	}
}


static int get_users_list () {

		if (user_list != NULL) {
			/* free previous cached user list */
			debug (1, "freeing previous user list");
			free (user_list);
			user_list = NULL;
			u_len = 0;
		}
		/*Call SP API to get list of users */
		int num_users = sp_list_users (&user_list, NULL);
        if (num_users <= 0) {
			debug (1, "sp_list_users() returned error or no user in realm (%d)", num_users);
			return -1;
        }
		u_len = num_users;
		u_idx = 0;
		get_user_list = 0;

		return 0;
}

enum nss_status _nss_sp_getpwent_r (struct passwd *result,
              char *buffer, size_t buflen, int *errnop) {

	SP_INIT;
	debug (2, "==> _nss_sp_getpwent_r");
	_nss_sp_enter ();
	if (get_user_list) {
		if (get_users_list () == -1) {
			_nss_sp_leave ();
			return NSS_STATUS_NOTFOUND;
		}		
	}

	/* Call SP API to get next entry */
	if (u_idx == u_len) {
		/* reached end of list */
		_nss_sp_leave ();
		return NSS_STATUS_NOTFOUND;
	}
	char *s = *(user_list + u_idx);
	enum nss_status rc = _nss_sp_getpwnam_r (strtok (s, "@"), result, buffer, buflen, errnop);
	*(s + strlen(s)) = '@';	
	u_idx++;
	_nss_sp_leave ();
	return rc;
}

enum nss_status _nss_sp_getpwuid_r (uid_t uid,
              struct passwd *result,
              char *buffer, size_t buflen, int *errnop) {
	enum nss_status rc;
	int i;

	SP_INIT;
	debug (2, "==> _nss_sp_getpwuid_r uid=0x%x", uid);

	/* hack to avoid 'su' delay */
	if ((int) uid == -1) {
		error ("nss_sp_getpwuid_r called with uid=-1");
		return NSS_STATUS_NOTFOUND;
	}

	/*
	 * As SecurePass doesn't provide an API to get the user attrs fron the uid, we need to scan the user's list
	 */
    _nss_sp_enter ();
	if (u_len <= 0) {
		/*Call SP API to get list of users */
		if (get_users_list () == -1) {
			_nss_sp_leave ();
			return NSS_STATUS_NOTFOUND;
		}		
	}
	for (i = 0; i < u_len; i++) {
		char *s = *(user_list + i);
		rc = _nss_sp_getpwnam_r (strtok (s, "@"), result, buffer, buflen, errnop);
		*(s + strlen(s)) = '@';	
		if (rc != NSS_STATUS_SUCCESS) {
			_nss_sp_leave ();
			return rc;
		}	
		if (uid == result->pw_uid) {
			_nss_sp_leave ();
			return NSS_STATUS_SUCCESS;
		}
	}
    _nss_sp_leave ();
	return NSS_STATUS_NOTFOUND;
}
