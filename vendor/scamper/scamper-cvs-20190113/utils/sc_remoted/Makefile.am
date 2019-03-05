AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_remoted

sc_remoted_SOURCES = \
	sc_remoted.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../scamper/scamper_linepoll.c \
	../../scamper/scamper_writebuf.c

sc_remoted_LDADD = ../../scamper/libscamperfile.la @OPENSSL_LIBS@
sc_remoted_LDFLAGS = @OPENSSL_LDFLAGS@

man_MANS = sc_remoted.1

CLEANFILES = *~ *.core
