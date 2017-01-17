/*
 *
 * Author: gplll <gplll1818@gmail.com>, Aug 2015
 *  
 * This program provides a minimal test of SecurePass PAM
 * To run the program, create file /etc/pam.s/pam_sp_client, wtih the following contents:
 * password   required   /lib/security/pam_sp.so debug
 * auth       required   /lib/security/pam_sp.so debug
 */

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
misc_conv,
NULL
};

char *user_pwd = NULL;
int setpwd = 0;
int authuser = 0;

void usage (char *program) {
	fprintf(stderr, "Usage: %s [-p user] [-a user] [-h]\n", program);
	fprintf(stderr, "       -p: set user password\n");
	fprintf(stderr, "       -a: authenticate user\n");
	fprintf(stderr, "       -h: display usage\n");
	fprintf(stderr, "either -p or -a options must be specified\n");
}

void get_options (int argc, char *argv[]) 
{
	int opt;
	while ((opt = getopt(argc, argv, "hp:a:")) != -1) {
		switch (opt) {
			case 'p':
				setpwd = 1;
				user_pwd = optarg;
			break;
			case 'a':
				authuser = 1;
				user_pwd = optarg;
			break;
			case 'h':
			default: /* '?' */
				usage (argv[0]);
				exit(0);
		}
	}
	if ((setpwd == 0) && (authuser == 0)) {
		usage (argv[0]);
		exit (0);
	}
}

void set_pwd (char * user) {
	pam_handle_t *pamh=NULL;
	int retval = pam_start("pam_sp_client", user, &conv, &pamh);

	if (retval == PAM_SUCCESS) {
		retval = pam_chauthtok(pamh, 0);
	} else {
		printf ("pam_start() returned error\n");
		return;
	}

	if (retval == PAM_SUCCESS) {
		printf ("password for user %s has been set\n", user);
	} else {
		printf ("pam_chauthtok() returned error %d for user %s\n", retval, user);
    }
	if (pam_end(pamh, retval) != PAM_SUCCESS) { 
		printf ("pam_end() returned error for user %s\n", user);
		return;
	}
}

void auth_user (char * user) {
	pam_handle_t *pamh=NULL;
	int retval = pam_start("pam_sp_client", user, &conv, &pamh);

	if (retval == PAM_SUCCESS) {
		retval = pam_authenticate(pamh, 0);
	} else {
		printf ("pam_start() returned error\n");
		return;
	}

	if (retval == PAM_SUCCESS) {
		printf ("user %s has been authenticated\n", user);
	} else {
		printf ("pam_authenticate() returned error %d for user %s\n", retval, user);
    }
	if (pam_end(pamh, retval) != PAM_SUCCESS) { 
		printf ("pam_end() returned error for user %s\n", user);
		return;
	}
}

int main(int argc, char *argv[])
{
	get_options (argc, argv);
	char *user = user_pwd;
	if (setpwd) {
		set_pwd (user);
	}
	if (authuser) {
		auth_user (user);
	}
#if 0
	user = strtok (user_pwd, " ");
	pwd = strtok (NULL, " ");
	if ((user == NULL) || (pwd == NULL)) {
		printf ("argument must be in the form 'user pwd'\n");
	}
	if (setpwd) {
		set_pwd (user, pwd);
	}
	if (authuser) {
		auth_user (user, pwd);
	}
#endif
	return 1;
}

