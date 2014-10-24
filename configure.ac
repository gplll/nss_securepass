#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nss_securepass], [1.0.0.0])
AC_CANONICAL_HOST
case $host_os in
  linux*)
        # OK, let's go on
        AC_MSG_NOTICE(your host_os is $host_os)
        ;;
    *)
        #Default Case
        AC_MSG_ERROR([Your operating system ($host_os) is not currently supported])
        ;;
esac

AC_CONFIG_SRCDIR([nss_sp.c])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for header files.
AC_CHECK_HEADER(netdb.h,, AC_MSG_ERROR(could not locate <netdb.h>))
AC_CHECK_HEADER(nss.h,, AC_MSG_ERROR(could not locate <nss.h>))
AC_CHECK_HEADER(pthread.h,, AC_MSG_ERROR(could not locate <pthread.h>))
AC_CHECK_HEADER(syslog.h,, AC_MSG_ERROR(could not locate <syslog.h>))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_LIB(curl, curl_easy_init,,AC_MSG_ERROR(libcurl development package  is missing - pls install it))

# check for gcc and set FLAGS
if test "$ac_cv_prog_gcc" = "yes"
then CFLAGS="$CFLAGS -Wall -fPIC"
else AC_MSG_ERROR(gcc is required - pls. install it) 
fi

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
