/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014
 *  
 */

#define error(fmt, args...) \
syslog(LOG_ERR, "nss_sp: %s:%d thread %u - " fmt, __FILE__, __LINE__, (uint)pthread_self() , ## args); \

#define debug(level, fmt, args...) \
if ((sp_config.debug >= level)) { \
syslog(LOG_DEBUG, "nss_sp: %s:%d thread %u - " fmt, __FILE__, __LINE__, (uint)pthread_self() , ## args); \
} \
else if ((sp_config.debug_stderr >= level)) { \
fprintf(stderr, "nss_sp: " fmt "\n" , ## args); \
}

# define NSS_SP_LOCK(m)		pthread_mutex_lock(&m)
# define NSS_SP_UNLOCK(m)	pthread_mutex_unlock(&m)

/* Acquire global nss_sp lock */
void _nss_sp_enter (void);
/* Release global nss_sp lock */
void _nss_sp_leave (void);
