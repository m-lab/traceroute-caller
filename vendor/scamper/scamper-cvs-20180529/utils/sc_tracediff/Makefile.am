AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_tracediff

sc_tracediff_SOURCES = \
	sc_tracediff.c \
	../../utils.c \
	../../mjl_splaytree.c

sc_tracediff_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_tracediff.1

CLEANFILES = *~ *.core
