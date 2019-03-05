AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_attach

sc_attach_SOURCES = \
	sc_attach.c \
	../../utils.c \
	../../mjl_list.c \
	../../scamper/scamper_writebuf.c \
	../../scamper/scamper_linepoll.c

man_MANS = sc_attach.1

CLEANFILES = *~ *.core
