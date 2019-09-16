AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_erosprober

sc_erosprober_SOURCES = \
	sc_erosprober.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_patricia.c \
	../../scamper/scamper_linepoll.c \
	../../scamper/scamper_writebuf.c

sc_erosprober_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_erosprober.1

CLEANFILES = *~ *.core
