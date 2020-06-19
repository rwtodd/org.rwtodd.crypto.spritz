#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([spritz], [1.0], [https://github.com/rwtodd/spritz_cipher])
AC_CONFIG_SRCDIR([src/b64.c])
AC_CONFIG_HEADERS([src/config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS(m4_normalize([stdbool.h fcntl.h stddef.h stdint.h stdlib.h
                  string.h termios.h unistd.h]),
		  [],
		  AC_MSG_ERROR([Missing a required header!]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
if test "x$ac_cv_func_malloc_0_nonnull" != "xyes" ; then
   AC_MSG_ERROR([Must have a working malloc!])
fi

AC_CHECK_FUNCS([memset],
               [],
	       AC_MSG_ERROR([Missing required stdlib function!]))

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
