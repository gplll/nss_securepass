/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014
 *  
 * Debug levels:
 * 1 --> errors
 * 2 --> at function enter + main facts
 * 3 --> more detail
 * 4 --> JSON processing
 */

/*
 *
 */
#define error(fmt, args...) \
if (sp_config.debug >= 1) { \
syslog(LOG_ERR, "nss_sp: %s:%d pid %u - " fmt, __FILE__, __LINE__, (uint)getpid() , ## args); \
}

#define debug(level, fmt, args...) \
if (sp_config.debug >= level) { \
syslog(LOG_DEBUG, "nss_sp: %s:%d pid %u - " fmt, __FILE__, __LINE__, (uint)getpid() , ## args); \
} \
else if (sp_config.debug_stderr >= level) { \
fprintf(stderr, "nss_sp: " fmt "\n" , ## args); \
}
