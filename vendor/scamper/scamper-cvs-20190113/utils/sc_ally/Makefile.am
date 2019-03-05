AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_ally

sc_ally_SOURCES = \
	sc_ally.c \
	../../scamper/scamper_linepoll.c \
	../../scamper/scamper_writebuf.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c

sc_ally_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_ally.1

CLEANFILES = *~ *.core
