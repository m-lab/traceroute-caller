AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_tbitblind

sc_tbitblind_SOURCES = \
	sc_tbitblind.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c

sc_tbitblind_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_tbitblind.1

CLEANFILES = *~ *.core
