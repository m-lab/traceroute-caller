AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_tbitpmtud

sc_tbitpmtud_SOURCES = \
	sc_tbitpmtud.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_prefixtree.c \
	../../mjl_splaytree.c

sc_tbitpmtud_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_tbitpmtud.1

CLEANFILES = *~ *.core
