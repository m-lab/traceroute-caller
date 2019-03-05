AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_speedtrap

sc_speedtrap_SOURCES = \
	sc_speedtrap.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../scamper/scamper_linepoll.c \
	../../scamper/scamper_writebuf.c

sc_speedtrap_CFLAGS = @PTHREAD_CFLAGS@
sc_speedtrap_LDFLAGS = @PTHREAD_CFLAGS@
sc_speedtrap_LDADD = ../../scamper/libscamperfile.la @PTHREAD_LIBS@

man_MANS = sc_speedtrap.1

CLEANFILES = *~ *.core
