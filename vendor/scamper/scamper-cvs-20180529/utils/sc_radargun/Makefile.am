AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_radargun

sc_radargun_SOURCES = \
	sc_radargun.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c

sc_radargun_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_radargun.1

CLEANFILES = *~ *.core
