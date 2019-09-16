AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_uptime

sc_uptime_SOURCES = \
	sc_uptime.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../mjl_prefixtree.c \
	../../scamper/scamper_linepoll.c \
	../../scamper/scamper_writebuf.c

sc_uptime_LDADD = ../../scamper/libscamperfile.la -lsqlite3

man_MANS = sc_uptime.1

CLEANFILES = *~ *.core
