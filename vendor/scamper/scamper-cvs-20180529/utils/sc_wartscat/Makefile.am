AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_wartscat

sc_wartscat_SOURCES = sc_wartscat.c ../../mjl_heap.c

sc_wartscat_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_wartscat.1

CLEANFILES = *~ *.core
