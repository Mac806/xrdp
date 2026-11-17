AM_CPPFLAGS = \
  -I$(top_builddir) \
  -I$(top_srcdir)/sesman/libsesman \
  -I$(top_srcdir)/common

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
                  $(top_srcdir)/tap-driver.sh

PACKAGE_STRING = "sesman"

TESTS = test_sesman
check_PROGRAMS = test_sesman

test_sesman_SOURCES = \
    test_sesman_main.c \
    test_sesman.h \
    test_login_ban.c \
    test_session_audit.c

test_sesman_CFLAGS = \
    @CHECK_CFLAGS@

test_sesman_LDADD = \
    $(top_builddir)/sesman/libsesman/libsesman.la \
    $(top_builddir)/common/libcommon.la \
    @CHECK_LIBS@
