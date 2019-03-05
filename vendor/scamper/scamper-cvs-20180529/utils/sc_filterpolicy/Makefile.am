AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_filterpolicy

sc_filterpolicy_SOURCES = \
	sc_filterpolicy.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../scamper/scamper_linepoll.c \
	../../scamper/scamper_writebuf.c

sc_filterpolicy_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_filterpolicy.1

CLEANFILES = *~ *.core
