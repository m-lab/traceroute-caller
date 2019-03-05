AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_ipiddump

sc_ipiddump_SOURCES = sc_ipiddump.c ../../mjl_list.c ../../utils.c

sc_ipiddump_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_ipiddump.1

CLEANFILES = *~ *.core
