AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_hoiho

sc_hoiho_SOURCES = \
	sc_hoiho.c \
	../../utils.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../mjl_threadpool.c \
	../../scamper/scamper_addr.c

sc_hoiho_CFLAGS = @PTHREAD_CFLAGS@ @PCRE_CFLAGS@
sc_hoiho_LDFLAGS = @PTHREAD_CFLAGS@ @PCRE_CFLAGS@
sc_hoiho_LDADD = @PTHREAD_LIBS@ @PCRE_LIBS@

man_MANS = sc_hoiho.1

CLEANFILES = *~ *.core
