AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_bdrmap

sc_bdrmap_SOURCES = \
	sc_bdrmap.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../mjl_prefixtree.c

sc_bdrmap_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_bdrmap.1

CLEANFILES = *~ *.core
