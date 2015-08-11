/*
 *
 * File: 	pam_sp.c
 * Author: 	gplll <gplll1818@gmail.com>, Aug 2015
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 * This program is derivative work of pam_radius.c code, 
 * taken from https://github.com/FreeRADIUS/pam_radius 
 *
 * pam_radius.c License NOTICE:
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * The original pam_radius.c code is copyright (c) Cristian Gafton, 1996,
 *                                             <gafton@redhat.com>
 *
 * Some challenge-response code is copyright (c) CRYPTOCard Inc, 1998.
 *                                              All rights reserved.
 */

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#define PAM_SM_ACCOUNT

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "sp_api.h"
#include "pam_sp.h"

#define SP_INIT \
    if ((sp_config.status != SP_INITED)) { \
        if (!(sp_init ())) return PAM_SERVICE_ERR; \
    }

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { return retval; }

/* argument parsing */
/* returns PAM_SUCCESS if success, PAM_SERVICE_ERR if error */
static int _pam_parse(int argc, const char **argv, sp_conf_t *conf)
{

	memset(conf, 0, sizeof(sp_conf_t)); /* ensure it's initialized */

	/*
	 *	If either is not there, then we can't parse anything.
	 */
	if ((argc == 0) || (argv == NULL)) {
		return PAM_SUCCESS;
	}

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp(*argv, "debug")) {
			conf->debug = 1;
		} 
		else if  (!strcmp(*argv, "debug_stderr")) {
            conf->debug_stderr = 1;
        }
		else {
			error ("unrecognized option: %s", *argv);
			return PAM_SERVICE_ERR; 
		}
	}
	return PAM_SUCCESS;
}

/* Callback function used to free the saved return value for pam_setcred. */
void _int_free(pam_handle_t * pamh, void *x, int error_status)
{
		free(x);
}

static int sp_converse(pam_handle_t *pamh, int msg_style, char *message, char **password)
{
	const struct pam_conv *conv;
	struct pam_message resp_msg;
	const struct pam_message *msg[1];
	struct pam_response *resp = NULL;
	int retval;

	resp_msg.msg_style = msg_style;
	resp_msg.msg = message;
	msg[0] = &resp_msg;

	/* grab the password */
	retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	PAM_FAIL_CHECK;

	retval = conv->conv(1, msg, &resp,conv->appdata_ptr);
	PAM_FAIL_CHECK;

	if (password) {		/* assume msg.type needs a response */
		/* I'm not sure if this next bit is necessary on Linux */

		*password = resp->resp;
		free(resp);
	}

	return PAM_SUCCESS;
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { \
	int *pret = malloc(sizeof(int)); \
	*pret = retval;	\
	pam_set_data(pamh, "sp_setcred_return", (void *) pret, _int_free);	\
	return retval; }

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
	const char *user;
	char *password = NULL;
	int retval;
	sp_conf_t config;

	retval = _pam_parse(argc, argv, &config);
	PAM_FAIL_CHECK;
	SP_INIT;
	debug (2, "==> pam_sm_authenticate");

	/* grab the user name */
	retval = pam_get_user(pamh, &user, NULL);
	PAM_FAIL_CHECK;

	/* check that they've entered something */
	if (user == NULL)  {
		retval = PAM_USER_UNKNOWN;
		PAM_FAIL_CHECK;
	}
	debug (2, "Got user name %s", user);

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {goto error; }

	/* grab the password (if any) from the previous authentication layer */
	retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &password);
	PAM_FAIL_CHECK;

	if (password) {
		password = strdup(password);
		/* debug (2, "Got password from PAM: %s", password); */
		debug (2, "Got password from PAM");
	}

	/* no previous password: get one from the user */
	if (!password) {
		retval = sp_converse(pamh, PAM_PROMPT_ECHO_OFF, "Password: ", &password);
		PAM_FAIL_CHECK;
	} 

	/* call securepass API */
	if (sp_user_auth_p (user, password) != -1) {
		retval = PAM_SUCCESS;
	} else {
		retval = PAM_AUTH_ERR;	/* authentication failure */

error:
		/* If there was a password pass it to the next layer */
		if (password && *password) {
			pam_set_item(pamh, PAM_AUTHTOK, password);
		}
	}

	debug (2, "authentication for user %s %s", user, retval==PAM_SUCCESS ? "succeeded":"failed");

	_pam_forget(password);

	int *pret = malloc(sizeof(int));
	*pret = retval;
	pam_set_data(pamh, "sp_setcred_return", (void *) pret, _int_free);

	return retval;
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { return retval; }

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
	int retval, *pret;
	sp_conf_t config;

	retval = _pam_parse(argc, argv, &config);
	PAM_FAIL_CHECK;
	SP_INIT;
	debug (2, "==> pam_sm_setcred, flags=0x%x argc=%d", flags, argc);

	retval = PAM_SUCCESS;
	pret = &retval;
	pam_get_data(pamh, "sp_setcred_return", (const void **) &pret);
	return (*pret==PAM_SUCCESS ? PAM_SUCCESS : PAM_CRED_ERR);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	sp_conf_t config;

	int retval = _pam_parse(argc, argv, &config);
	PAM_FAIL_CHECK;
	SP_INIT;
	debug (2, "==> pam_sm_open_session() called...returning PAM_SUCCESS");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	sp_conf_t config;

	int retval = _pam_parse(argc, argv, &config);
	PAM_FAIL_CHECK;
	SP_INIT;
	debug (2, "==> pam_sm_close_session() called...returning PAM_SUCCESS");
	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	char *password = NULL;
	char *new_password = NULL;
	char *check_password = NULL;
	int retval = PAM_AUTHTOK_ERR;
	int attempts;
	sp_conf_t config;

	retval = _pam_parse(argc, argv, &config);
	PAM_FAIL_CHECK;
	SP_INIT;
	debug (2, "==> pam_sm_chauthtok, flags=0x%x argc=%d", flags, argc);
	/*
     * check args, only accept debug, otherwise return error
     */
	/* grab the user name */
	retval = pam_get_user(pamh, &user, NULL);
	PAM_FAIL_CHECK;

	/* check that they've entered something */
	if (user == NULL) {
		return PAM_USER_UNKNOWN;
	}
	debug (2, "user=%s", user);

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {goto error; }

	/* grab the old password (if any) from the previous password layer */
	retval = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &password);
	PAM_FAIL_CHECK;
	if (password) {
		password = strdup(password);
		/* debug (2, "old pwd= %s", password); */
		debug (2, "got old pwd from previous layer");
	}

	/* grab the new password (if any) from the previous password layer */
	retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &new_password);
	PAM_FAIL_CHECK;
	if (new_password) {
		new_password = strdup(new_password);
		/* debug (2, "new pwd= %s", new_password); */
		debug (2, "got new pwd from previous layer");
	}

	/* preliminary password change checks. */
	if (flags & PAM_PRELIM_CHECK) {
		if (!password) {		/* no previous password: ask for one */
			retval = sp_converse(pamh, PAM_PROMPT_ECHO_OFF, "Securepass password: ", &password);
			PAM_FAIL_CHECK;
		}
		/*
		 * We now check the password to see if it's the right one.
		 * If it isn't, we let the user try again.
		 */

		/* call securepass API */
 		if (sp_user_auth_p (user, password) == -1) {
            debug (4, "old password for user %s is wrong\n", user);
			_pam_forget(password);
			retval = PAM_PERM_DENIED;
			goto error;
        } else {
            debug (4, "old password for user %s is correct\n", user);
        }

		/*
		 * We're now sure it's the right user.
		 * Ask for their new password, if appropriate
		 */

		if (!new_password) {	/* not found yet: ask for it */
			int new_attempts;
			attempts = 0;

			/* loop, trying to get matching new passwords */
			while (attempts++ < 3) {

				/* loop, trying to get a new password */
				new_attempts = 0;
				while (new_attempts++ < 3) {
					retval = sp_converse (pamh, PAM_PROMPT_ECHO_OFF,
							"New password: ", &new_password);
					PAM_FAIL_CHECK;

					if (strcmp(password, new_password) == 0) { /* are they the same? */
						sp_converse(pamh, PAM_ERROR_MSG,
						 "You must choose a new password.", NULL);
						_pam_forget(new_password);
						continue;
					}

					break;		/* the new password is OK */
				}

				if (new_attempts >= 3) { /* too many new password attempts: die */
					retval = PAM_AUTHTOK_ERR;
					goto error;
				}

				/* make sure of the password by asking for verification */
				retval = sp_converse(pamh, PAM_PROMPT_ECHO_OFF,
						      "New password (again): ", &check_password);
				PAM_FAIL_CHECK;

				retval = strcmp(new_password, check_password);
				_pam_forget(check_password);

				/* if they don't match, don't pass them to the next module */
				if (retval != 0) {
					_pam_forget(new_password);
					sp_converse(pamh, PAM_ERROR_MSG,
								 "You must enter the same password twice.", NULL);
					retval = PAM_AUTHTOK_ERR;
					goto error;		/* ??? maybe this should be a 'continue' ??? */
				}

				break;			/* everything's fine */
			}	/* loop, trying to get matching new passwords */

			if (attempts >= 3) { /* too many new password attempts: die */
				retval = PAM_AUTHTOK_ERR;
				goto error;
			}
		} /* now we have a new password which passes all of our tests */

	} else if (flags & PAM_UPDATE_AUTHTOK) {

		if (!password || !new_password) { /* ensure we've got passwords */
			retval = PAM_AUTHTOK_ERR;
			goto error;
		}

		/* call SP API to change the passwd */
 		if (sp_user_password_change_p (user, new_password) == -1) {
            debug (4, "can't set new password for user %s\n", user);
			retval = PAM_AUTHTOK_ERR;
			goto error;
        } else {
            debug (4, "new password for user %s has been set\n", user);
        }
	}

	/*
	 * Send the passwords to the next stage if preliminary checks fail,
	 * or if the password change request fails.
	 */
	if ((flags & PAM_PRELIM_CHECK) || (retval != PAM_SUCCESS)) {
	error:

		/* If there was a password pass it to the next layer */
		if (password && *password) {
			pam_set_item(pamh, PAM_OLDAUTHTOK, password);
		}

		if (new_password && *new_password) {
			pam_set_item(pamh, PAM_AUTHTOK, new_password);
		}
	}

	debug (2, "password change %s", retval==PAM_SUCCESS ? "succeeded" : "failed");

	_pam_forget(password);
	_pam_forget(new_password);
	return retval;
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { return retval; }

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
	sp_conf_t config;

	int retval = _pam_parse(argc, argv, &config);
	PAM_FAIL_CHECK;
	SP_INIT;
	debug (2, "==> pam_sm_acct_mgmt() called...returning PAM_SUCCESS");
	return PAM_SUCCESS;
}
