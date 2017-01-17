/*
 * File: 	pam_sp.h
 * Author: 	gplll <gplll1818@gmail.com>, Aug 2015
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 * This program is derivative work of pam_radius.c code, 
 * taken from https://github.com/FreeRADIUS/pam_radius 
 */

typedef struct sp_conf_t {
	int debug;
	int debug_stderr;
} sp_conf_t;

#define PAM_DEBUG			1
#define PAM_DEBUG_STDERR	2

#define error(fmt, args...) \
syslog(LOG_AUTHPRIV|LOG_ERR, "pam_sp: thread %u - error: " fmt, (uint)pthread_self() , ## args); \

#define debug(level, fmt, args...) \
if ((config.debug)) { \
syslog(LOG_AUTHPRIV|LOG_DEBUG, "pam_sp: thread %u - " fmt, (uint)pthread_self() , ## args); \
} \
else if ((config.debug_stderr)) { \
fprintf(stderr, "pam_sp: " fmt "\n" , ## args); \
}

#define _pam_forget(X) if (X) {memset(X, 0, strlen(X));free(X);X = NULL;}

