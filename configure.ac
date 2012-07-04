AC_INIT([p0f version 3 dlfunc for Exim], [0.1], [snabb@epipe.com],
  [exim-p0f3-dlfunc], [http://dist.epipe.com/exim/])

AC_CONFIG_SRCDIR([exim-p0f3-dlfunc.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign])
LT_INIT

AC_PROG_CC
AC_PROG_CC_C99

AC_CHECK_HEADER([local_scan.h], [],
  [AC_MSG_ERROR([Required Exim local_scan.h include file was not found])])

AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

AC_OUTPUT
