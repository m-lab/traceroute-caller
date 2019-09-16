# $Id: Makefile.am,v 1.34 2019/07/28 09:24:53 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = scamper

lib_LTLIBRARIES = libscamperfile.la

libscamperfile_la_LDFLAGS = -version-info 0:0:0

libscamperfile_la_SOURCES = \
	../mjl_splaytree.c \
	../utils.c \
	scamper_file.c \
	scamper_file_arts.c \
	scamper_file_warts.c \
	scamper_file_text.c \
	scamper_file_json.c \
	scamper_addr.c \
	scamper_list.c \
	scamper_icmpext.c \
	trace/scamper_trace.c \
	trace/scamper_trace_warts.c \
	trace/scamper_trace_text.c \
	trace/scamper_trace_json.c \
	ping/scamper_ping.c \
	ping/scamper_ping_warts.c \
	ping/scamper_ping_text.c \
	ping/scamper_ping_json.c \
	tracelb/scamper_tracelb.c \
	tracelb/scamper_tracelb_warts.c \
	tracelb/scamper_tracelb_text.c \
	tracelb/scamper_tracelb_json.c \
	dealias/scamper_dealias.c \
	dealias/scamper_dealias_warts.c \
	dealias/scamper_dealias_text.c \
	dealias/scamper_dealias_json.c \
	sting/scamper_sting.c \
	sting/scamper_sting_warts.c \
	sting/scamper_sting_text.c \
	neighbourdisc/scamper_neighbourdisc.c \
	neighbourdisc/scamper_neighbourdisc_warts.c \
	tbit/scamper_tbit.c \
	tbit/scamper_tbit_warts.c \
	tbit/scamper_tbit_text.c \
	tbit/scamper_tbit_json.c \
	sniff/scamper_sniff.c \
	sniff/scamper_sniff_warts.c \
	host/scamper_host.c \
	host/scamper_host_warts.c

scamper_SOURCES = \
	../mjl_list.c \
	../mjl_heap.c \
	../mjl_splaytree.c \
	../mjl_patricia.c \
	../utils.c \
	scamper.c \
	scamper_osinfo.c \
	scamper_addr.c \
	scamper_list.c \
	scamper_debug.c \
	scamper_udp4.c \
	scamper_udp6.c \
	scamper_icmp4.c \
	scamper_icmp6.c \
	scamper_icmp_resp.c \
	scamper_icmpext.c \
	scamper_tcp4.c \
	scamper_tcp6.c \
	scamper_ip6.c \
	scamper_ip4.c \
	scamper_if.c \
	scamper_rtsock.c \
	scamper_dl.c \
	scamper_addr2mac.c \
	scamper_fds.c \
	scamper_linepoll.c \
	scamper_writebuf.c \
	scamper_dlhdr.c \
	scamper_privsep.c \
	scamper_getsrc.c \
	scamper_control.c \
	scamper_firewall.c \
	scamper_outfiles.c \
	scamper_probe.c \
	scamper_task.c \
	scamper_queue.c \
	scamper_cyclemon.c \
	scamper_options.c \
	scamper_file.c \
	scamper_file_arts.c \
	scamper_file_warts.c \
	scamper_file_text.c \
	scamper_file_json.c \
	scamper_sources.c \
	scamper_source_cmdline.c \
	scamper_source_control.c \
	scamper_source_file.c \
	scamper_source_tsps.c \
	trace/scamper_trace.c \
	trace/scamper_trace_warts.c \
	trace/scamper_trace_text.c \
	trace/scamper_trace_json.c \
	trace/scamper_trace_do.c \
	ping/scamper_ping.c \
	ping/scamper_ping_warts.c \
	ping/scamper_ping_text.c \
	ping/scamper_ping_json.c \
	ping/scamper_ping_do.c \
	tracelb/scamper_tracelb.c \
	tracelb/scamper_tracelb_warts.c \
	tracelb/scamper_tracelb_text.c \
	tracelb/scamper_tracelb_json.c \
	tracelb/scamper_tracelb_do.c \
	dealias/scamper_dealias.c \
	dealias/scamper_dealias_warts.c \
	dealias/scamper_dealias_text.c \
	dealias/scamper_dealias_json.c \
	dealias/scamper_dealias_do.c \
	sting/scamper_sting.c \
	sting/scamper_sting_warts.c \
	sting/scamper_sting_text.c \
	sting/scamper_sting_do.c \
	neighbourdisc/scamper_neighbourdisc.c \
	neighbourdisc/scamper_neighbourdisc_warts.c \
	neighbourdisc/scamper_neighbourdisc_do.c \
	tbit/scamper_tbit.c \
	tbit/scamper_tbit_warts.c \
	tbit/scamper_tbit_text.c \
	tbit/scamper_tbit_json.c \
	tbit/scamper_tbit_do.c \
	sniff/scamper_sniff.c \
	sniff/scamper_sniff_warts.c \
	sniff/scamper_sniff_do.c \
	host/scamper_host.c \
	host/scamper_host_warts.c \
	host/scamper_host_do.c

scamper_CFLAGS = $(AM_CFLAGS)

scamper_LDADD = @OPENSSL_LIBS@
scamper_LDFLAGS = @OPENSSL_LDFLAGS@

include_HEADERS = \
	scamper_file.h \
	scamper_addr.h \
	scamper_list.h \
	scamper_icmpext.h \
	trace/scamper_trace.h \
	ping/scamper_ping.h \
	tracelb/scamper_tracelb.h \
	dealias/scamper_dealias.h \
	sting/scamper_sting.h \
	neighbourdisc/scamper_neighbourdisc.h \
	tbit/scamper_tbit.h \
	sniff/scamper_sniff.h \
	host/scamper_host.h

man_MANS = \
	scamper.1 \
	libscamperfile.3 \
	warts.5

CLEANFILES = *~ *.core \
	trace/*~ ping/*~ tracelb/*~ dealias/*~ sting/*~ \
	neighbourdisc/*~ tbit/*~ sniff/*~ host/*~
