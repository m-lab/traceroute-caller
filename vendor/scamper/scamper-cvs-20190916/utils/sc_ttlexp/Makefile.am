AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_ttlexp

sc_ttlexp_SOURCES = \
	sc_ttlexp.c \
	../../mjl_splaytree.c \
	../../mjl_prefixtree.c

sc_ttlexp_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_ttlexp.1

CLEANFILES = *~ *.core
