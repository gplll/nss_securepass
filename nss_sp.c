/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014 - Feb 2017
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
#include <grp.h>
#include <curl/curl.h>
#include "jsmn.h"
#include "sp_api.h"
#include "nss_sp.h"

#define SP_INIT \
	if ((sp_config.status != SP_INITED)) { \
        if (sp_init () == -1) return NSS_STATUS_UNAVAIL; \
   	}

typedef struct {
	char valid;
	gid_t gid;
} group_gid_t;

static pthread_mutex_t sp_users_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock protecting the cached user list */
static pthread_mutex_t sp_groups_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock protecting the cached group list */
static int get_user_list = 0;  /* if 1, user list must be read by SP. 
                                  Set to 1 by _nss_sp_setpwent() and _nss_sp_endpwent() */ 
static char **user_list = NULL; /* pointer to cached user list */
static int u_len = 0;	/* number of users in cached user list */
static int u_idx; 	/* Index of next user within the cached user list to be returned to getpwent_r */

static int get_group_list = 0;  /* if 1, group list must be read by SP. 
                                  Set to 1 by _nss_sp_setgrent() and _nss_sp_endgrent() */ 
static char **group_list = NULL; /* pointer to cached group list */
static int g_len = 0;	/* number of groups in cached group list */
static int g_idx; 	/* Index of next group within the cached group list to be returned to getpwent_r */
static group_gid_t *group_gids; /* pointer to cached gids */

# define SP_USERS_ENTER		pthread_mutex_lock (&sp_users_lock)
# define SP_USERS_LEAVE		pthread_mutex_unlock (&sp_users_lock)
# define SP_GROUPS_ENTER	pthread_mutex_lock (&sp_groups_lock)
# define SP_GROUPS_LEAVE	pthread_mutex_unlock (&sp_groups_lock)

enum nss_status _nss_sp_setpwent (void) {

	SP_INIT;
	debug (2, "==> _nss_sp_setpwent");
	SP_USERS_ENTER;
	get_user_list = 1;
	SP_USERS_LEAVE;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sp_endpwent (void) {
	SP_INIT;
	debug (2, "==> _nss_sp_endpwent");
	SP_USERS_ENTER;
	get_user_list = 1;
	SP_USERS_LEAVE;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sp_getpwnam_r (const char *name,
              struct passwd *result,
              char *buffer, size_t buflen, int *errnop) {

	sp_users_xattrs_t *xattrs;

	SP_INIT;
	debug (2, "==> _nss_sp_getpwnam_r (%s)", name);

	/* hack to avoid bash completion issue */
	if (strcmp (name, "*") == 0) {
		return NSS_STATUS_NOTFOUND;
	}

	/* call SP API */
	int rc = sp_users_xattrs_p (&xattrs, name, 1);
	if (rc == -1) {
		debug (2, "sp_users_xattrs() returned error");
		return NSS_STATUS_NOTFOUND;
	} else {
		/* check buffer space */
		if (xattrs->size > buflen) {
			*errnop = ERANGE;
			free (xattrs);
			debug (2, "buffer is too small, returning NSS_STATUS_TRYAGAIN");
			return NSS_STATUS_TRYAGAIN;
		}

		/* Fill the output fields */
		int pos = 0;

		if ((xattrs->posixuid[0] == 0) || (xattrs->posixgid[0] == 0)) {
			/* uid or gid are not defined - not a valid posix user */
			free (xattrs);
			return NSS_STATUS_NOTFOUND;
		}
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
			debug (2, "freeing previous user list");
			free (user_list);
			user_list = NULL;
			u_len = 0;
		}
		/*Call SP API to get list of users */
		int num_users = sp_users_list (&user_list, NULL);
        if (num_users <= 0) {
			debug (2, "sp_users_list() returned error or no user in realm (%d)", num_users);
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
	SP_USERS_ENTER;
	if (get_user_list) {
		if (get_users_list () == -1) {
			SP_USERS_LEAVE;
			return NSS_STATUS_NOTFOUND;
		}		
	}

	/* We loop because we need to discard users where uid or gid is not defined */
	char *s;
	enum nss_status rc;
	while (1) {
		/* Call SP API to get next entry */
		if (u_idx == u_len) {
			/* reached end of list */
			SP_USERS_LEAVE;
			return NSS_STATUS_NOTFOUND;
		}
		s = *(user_list + u_idx);
		rc = _nss_sp_getpwnam_r (strtok (s, "@"), result, buffer, buflen, errnop);
		*(s + strlen(s)) = '@';	 /* restore the char removed by strtok */
		u_idx++;
		if (rc == NSS_STATUS_SUCCESS) {
			break;
		} else {
			/* get next user */
			continue;
		}
	}
	SP_USERS_LEAVE;
	return rc;
}

enum nss_status _nss_sp_getpwuid_r (uid_t uid,
              struct passwd *result,
              char *buffer, size_t buflen, int *errnop) {
	enum nss_status rc;
	int i;

	SP_INIT;
	debug (2, "==> _nss_sp_getpwuid_r (0x%x)", uid);

	/* hack to avoid 'su' delay */
	if ((int) uid == -1) {
		error ("nss_sp_getpwuid_r called with uid=-1");
		return NSS_STATUS_NOTFOUND;
	}

	/*
	 * As SecurePass doesn't provide an API to get the user attrs fron the uid, we need to scan the user's list
	 */
    SP_USERS_ENTER;
	if (u_len <= 0) {
		/*Call SP API to get list of users */
		if (get_users_list () == -1) {
			SP_USERS_LEAVE;
			return NSS_STATUS_NOTFOUND;
		}		
	}
	for (i = 0; i < u_len; i++) {
		char *s = *(user_list + i);
		rc = _nss_sp_getpwnam_r (strtok (s, "@"), result, buffer, buflen, errnop);
		*(s + strlen(s)) = '@';	 /* restore the char removed by strtok */
		if (rc != NSS_STATUS_SUCCESS) {
			if (i < (u_len - 1)) {
				/* not at the end of the list - get next user */
				continue;
			}
			SP_USERS_LEAVE;
			return rc;
		}	
		if (uid == result->pw_uid) {
			SP_USERS_LEAVE;
			return NSS_STATUS_SUCCESS;
		}
	}
    SP_USERS_LEAVE;
	return NSS_STATUS_NOTFOUND;
}


enum nss_status _nss_sp_setgrent (void) {
	SP_INIT;
	debug (2, "==> _nss_sp_setgrent");
	SP_GROUPS_ENTER;
	get_group_list = 1;
	SP_GROUPS_LEAVE;
	return NSS_STATUS_SUCCESS;
} 

enum nss_status _nss_sp_endgrent (void) {
	SP_INIT;
	debug (2, "==> _nss_sp_endgrent");
	SP_GROUPS_ENTER;
	get_group_list = 1;
	SP_GROUPS_LEAVE;
	return NSS_STATUS_SUCCESS;
} 

/* 
 * this is the internal implementation of _nss_sp_getgrnam_r 
 * it has the same parameters than _nss_sp_getgrnam_r plus gid.
 * gid: if -1, ask the gid to sp_groups_xattrs, otherwise use the value passed
 */
static enum nss_status do_nss_sp_getgrnam_r (const char *name, struct group *result, 
              char *buffer, size_t buflen, int *errnop, gid_t gid) {

	int i;
	SP_INIT;
	debug (2, "==> do_nss_sp_getgrnam_r (%s, %d)", name, gid);

	if (gid == (gid_t) -1) {
		sp_groups_xattrs_t *xattrs;

	    /* call SP API to get the GID*/
	    int rc = sp_groups_xattrs_p (&xattrs, name);
	    if (rc == -1) {
		    debug (2, "sp_users_xattrs() returned error");
		    return NSS_STATUS_NOTFOUND;
		} else {
			if (xattrs->posixgid[0] == 0) {
				/* gid is not defined - not a valid posix group */
				free (xattrs);
				return NSS_STATUS_NOTFOUND;
			}
			result->gr_gid = strtoul(xattrs->posixgid, NULL, 10);
			free (xattrs);
		}	
	}
	else {
		/* fill the GID with the passed parameter */
		result->gr_gid = gid;
	}	
	/* get group members from sp_groups_members_list() */
	char **members;
	int len = sp_groups_members_list (&members, name, NULL);
	if (len == -1) {
		debug (2, "sp_groups_members_list() returned error...returning an empty list to caller");
		len = 0;
	} 
	/* check buffer space */
	int pos;  /* first free position within buffer where to write member strings */
	int newpos;
	if ((pos = strlen (name) + 1 + ((len + 1) * sizeof (char *))) > buflen) {
		*errnop = ERANGE;
		debug (2, "buffer is too small, returning NSS_STATUS_TRYAGAIN");
		return NSS_STATUS_TRYAGAIN;
	}
	/* fill output values */
	result->gr_passwd = NULL;
	strcpy (buffer, name);
	char **ptr = (char **) (buffer + strlen (name) + 1); /* first free position within buffer where 
															to write member pointers*/
	result->gr_mem = ptr;
	if (len > 0) {
		/* fill members strings */
		for (i = 0; i < len; i++) {
			if ((newpos = (pos + strlen (members[i]) + 1)) > buflen) {
				*errnop = ERANGE;
				debug (2, "buffer size=%d, required size=%d, returning NSS_STATUS_TRYAGAIN", 
						(int) buflen, newpos);
				return NSS_STATUS_TRYAGAIN;
			} 
			*ptr = buffer + pos; 
			debug (3, "copying member %s", members[i]);
			strcpy ((buffer + pos), strtok (members[i], "@")); 
			ptr++;
			pos = newpos;
		}
		free (members);
	}
	/* end the member list by filling next pointer to NULL */
	*ptr = NULL;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sp_getgrnam_r (const char *name, struct group *result, 
              char *buffer, size_t buflen, int *errnop) {
	return do_nss_sp_getgrnam_r (name, result, buffer, buflen, errnop, -1);
}

/* this function must be called when holding the group list lock */ 
static int get_groups_list () {

	debug (2, "==> get_groups_list");
	if (group_list != NULL) {
		/* free previous cached group list */
		debug (3, "freeing previous group list");
		free (group_list);
		group_list = NULL;
		g_len = 0;
	}
	/*Call SP API to get list of groups */
	int num_groups = sp_groups_list (&group_list, NULL);
	if (num_groups <= 0) {
		debug (2, "sp_groups_list() returned error or no group in realm (%d)", num_groups);
		return -1;
	}
	g_len = num_groups;
	g_idx = 0;
	get_group_list = 0;

	/*
	 * for each group, we get the GID and cache it, so we can answer quickly to _nss_sp_getgrid_r() requests
	 */ 

	if ((group_gids = malloc (sizeof (group_gid_t) * g_len)) == NULL) {
			error ("malloc() failed");
			return -1;
	}
	int i;
	sp_groups_xattrs_t *xattrs;
	for (i = 0; i < g_len; i++) {
		char *s = *(group_list + i);

		/* call SP API */
		int rc = sp_groups_xattrs (&xattrs, s);
		if (rc == -1) {
			debug (2, "sp_users_xattrs() returned error");
			group_gids[i].valid = 0;
		} else {
			if (xattrs->posixgid[0] == 0) {
				/* gid is not defined - not a valid posix group */
				debug (3, "group %s doesn't have a GID associated", s);
				group_gids[i].valid = 0;
			}
			else {
				/* cache the GID */
				debug (3, "caching GID=%s for group %s", xattrs->posixgid, s);
				group_gids[i].valid = 1;
				group_gids[i].gid = strtoul(xattrs->posixgid, NULL, 10);
			}
		}
	}
	return 0;
}

enum nss_status _nss_sp_getgrent_r (struct group *result,
              char *buffer, size_t buflen, int *errnop) {

	SP_INIT;
	debug (2, "==> _nss_sp_getgrent_r");
	SP_GROUPS_ENTER;
	if (get_group_list) {
		if (get_groups_list () == -1) {
			SP_GROUPS_LEAVE;
			return NSS_STATUS_NOTFOUND;
		}		
	}

	/* We loop because we need to discard groups where uid or gid is not defined */
	char *s;
	enum nss_status rc;
	while (1) {
		/* Call SP API to get next entry */
		if (g_idx == g_len) {
			/* reached end of list */
			SP_GROUPS_LEAVE;
			return NSS_STATUS_NOTFOUND;
		}
		s = *(group_list + g_idx);
		if (group_gids[g_idx].valid) {
			/* get group by name re-using the cached gid */
			rc = do_nss_sp_getgrnam_r (strtok (s, "@"), result, buffer, buflen, errnop, group_gids[g_idx].gid);
			*(s + strlen(s)) = '@';	 /* restore the char removed by strtok */
			g_idx++;
			break;
		}
		/* move to next group */
		g_idx++;
	}
	SP_GROUPS_LEAVE;
	return rc;
}

enum nss_status _nss_sp_getgrgid_r (gid_t gid,
              struct group *result,
              char *buffer, size_t buflen, int *errnop) {
	int i;
	SP_INIT;
	debug (2, "==> _nss_sp_getgrgid_r (%u)", gid);

	SP_GROUPS_ENTER;
	/*
	 * if group list is not cached, cache it
     */
 	if ((group_list == NULL) || (get_group_list)) {
		if (get_groups_list () == -1) {
			SP_GROUPS_LEAVE;
			return NSS_STATUS_NOTFOUND;
		}		
	}
	/*
	 * search the gid within the cached list
     */
	for (i = 0; i < g_len; i++) {
		if ((group_gids[i].valid) && (gid == group_gids[i].gid)) { /* group found */
			SP_GROUPS_LEAVE;
			/* use a temporary string to hold the username without realm */
			/* we cannot modify group_list[i] string as we're outside the groups critical region */		    
			char s[strlen (group_list[i]) + 1];
			strcpy (s, group_list[i]);
			return do_nss_sp_getgrnam_r (strtok (s, "@"), result, buffer, buflen, errnop, gid); 
		}	
	}	
	debug (2, "group %u not found", gid);
	SP_GROUPS_LEAVE;
	return NSS_STATUS_NOTFOUND;
} 
