/*
 * utils.h
 *
 * $Id: utils.h,v 1.115 2017/07/12 07:34:02 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2015      Matthew Luckie
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __UTILS_H
#define __UTILS_H

/*
 * Functions for dealing with time and timestamps
 */

int timeval_cmp(const struct timeval *a, const struct timeval *b);

int timeval_diff_ms(const struct timeval *a, const struct timeval *b);
int timeval_diff_us(const struct timeval *a, const struct timeval *b);
void timeval_diff_tv(struct timeval *rtt,
		     const struct timeval *from, const struct timeval *to);

void timeval_add_cs(struct timeval *out, const struct timeval *in, int cs);
void timeval_add_ms(struct timeval *out, const struct timeval *in, int ms);
void timeval_add_us(struct timeval *out, const struct timeval *in, int us);
void timeval_add_tv(struct timeval *tv, const struct timeval *add);
void timeval_add_tv3(struct timeval *out, const struct timeval *a,
		     const struct timeval *b);
void timeval_add_s(struct timeval *out, const struct timeval *in, int s);
void timeval_sub_us(struct timeval *out, const struct timeval *in, int us);
void timeval_cpy(struct timeval *dst, const struct timeval *src);
int timeval_inrange_us(const struct timeval *a,const struct timeval *b,int c);
char *timeval_tostr_us(const struct timeval *rtt, char *str, size_t len);

void gettimeofday_wrap(struct timeval *tv);

int fstat_mtime(int fd, time_t *mtime);
int stat_mtime(const char *filename, time_t *mtime);

/*
 * Functions for dealing with memory allocation
 */
#ifndef DMALLOC
#ifdef HAVE_CALLOC
#define malloc_zero(size) calloc(1, (size))
#else
void *malloc_zero(const size_t size);
#endif
void *memdup(const void *ptr, const size_t len);
int   realloc_wrap(void **ptr, size_t len);
#else
int   realloc_wrap_dm(void **ptr,size_t len, const char *file,const int line);
void *malloc_zero_dm(const size_t size, const char *file, const int line);
#define realloc_wrap(ptr, len) realloc_wrap_dm((ptr),(len), __FILE__,__LINE__)
#define malloc_zero(size) malloc_zero_dm((size), __FILE__, __LINE__)
#define memdup(ptr, len) memcpy(malloc(len), ptr, len)
#endif

void mem_concat(void *dst,const void *src,size_t len,size_t *off,size_t size);

typedef int (*array_cmp_t)(const void *va, const void *vb);
void *array_find(void **a, int nmemb, const void *item, array_cmp_t cmp);
int array_findpos(void **a, int nmemb, const void *item, array_cmp_t cmp);
void array_remove(void **, int *nmemb, int pos);
void array_qsort(void **a, int n, array_cmp_t cmp);

#ifndef DMALLOC
int array_insert(void ***a, int *nmemb, void *item, array_cmp_t cmp);
int array_insert_gb(void ***a, int *nmemb, int *mmemb, int growby,
		    void *item, array_cmp_t cmp);
#else
int array_insert_dm(void ***a, int *nmemb, void *item, array_cmp_t cmp,
		    const char *file, const int line);
int array_insert_gb_dm(void ***a, int *nmemb, int *mmemb, int growby,
		       void *item, array_cmp_t cmp,
		       const char *file, const int line);
#define array_insert(a, nmemb, item, cmp) \
  array_insert_dm((a), (nmemb), (item), (cmp), __FILE__, __LINE__)
#define array_insert_gb(a, nmemb, mmemb, growby, item, cmp) \
  array_insert_gb_dm((a), (nmemb), (mmemb), (growby), (item), (cmp), \
		     __FILE__, __LINE__)
#endif

/*
 * Functions for dealing with raw IPv4/IPv6 addresses
 */
int addr4_cmp(const void *a, const void *b);
int addr4_human_cmp(const void *a, const void *b);
int addr6_cmp(const void *a, const void *b);
int addr6_human_cmp(const void *a, const void *b);
int addr_cmp(const int af, const void *a, const void *b);
void *addr_dup(const int af, const void *addr);
const char *addr_tostr(int af, const void *addr, char *buf, size_t len);

/*
 * Functions for dealing with sockaddr addresses
 */

int sockaddr_compose(struct sockaddr *sa,
		     const int af, const void *addr, const int port);
int sockaddr_compose_un(struct sockaddr *sa, const char *name);
int sockaddr_compose_str(struct sockaddr *sa, const char *ip, const int port);
int sockaddr_len(const struct sockaddr *sa);
struct sockaddr *sockaddr_dup(const struct sockaddr *sa);
char *sockaddr_tostr(const struct sockaddr *sa, char *buf, const size_t len);

/*
 * Functions for dealing with fcntl flags on a file descriptor
 */

int fcntl_set(const int fd, const int flags);
int fcntl_unset(const int fd, const int flags);

/*
 * Functions for parsing strings
 */
char *string_nextword(char *str);
char *string_nullterm(char *str, const char *delim, char **next);
char *string_nullterm_char(char *str, const char delim, char **next);
int   string_isprint(const char *str, const size_t len);
int   string_isnumber(const char *str);
int   string_isfloat(const char *str);
int   string_tolong(const char *str, long *l);
char *string_lastof(char *str, const char *delim);
char *string_lastof_char(char *str, const char delim);
char *string_firstof_char(char *str, const char delim);
char *string_concat(char *str, size_t len, size_t *off, const char *fs, ...);
const char *string_findlc(const char *str, const char *find);
int   string_addrport(const char *in, char **addr, int *port);

/* check the character to see if it is possibly hex */
int ishex(char c);
uint8_t hex2byte(char a, char b);
void byte2hex(uint8_t byte, char *a);

/* functions for extracting and inserting values from byte arrays */
uint16_t bytes_ntohs(const uint8_t *);
uint32_t bytes_ntohl(const uint8_t *);
void bytes_htons(uint8_t *, uint16_t);
void bytes_htonl(uint8_t *, uint32_t);

/*
 * Functions for doing I/O
 */

int read_wrap(const int fd, void *ptr, size_t *rc, const size_t rt);
int write_wrap(const int fd, const void *ptr, size_t *wc, const size_t wt);

#ifndef _WIN32
int mkdir_wrap(const char *path, mode_t mode);
#else
int mkdir_wrap(const char *path);
#endif

/*
 * Functions for dealing with sysctls
 */

#if !defined(__sun__) && !defined (_WIN32)
int sysctl_wrap(int *mib, u_int len, void **buf, size_t *size);
#endif

/* function for formatting an off_t */
char *offt_tostr(char *buf, size_t len, off_t off, int lz, char m);

/*
 * Function for computing an Internet checksum
 */

uint16_t in_cksum(const void *buf, size_t len);

/* generate a 32-bit random number and return it */
void random_seed(void);
int random_u32(uint32_t *r);
int random_u16(uint16_t *r);
int random_u8(uint8_t *r);

/* fisher-yates shuffle */
int shuffle16(uint16_t *array, int len);
int shuffle32(uint32_t *array, int len);

/* count the number of bits set */
int countbits32(uint32_t v);

/*
 * Functions for uuencode and uudecode.
 */
int uuencode(const uint8_t *in, size_t ilen, uint8_t **out, size_t *olen);
size_t uuencode_len(size_t ilen, size_t *complete, size_t *leftover);
size_t uuencode_bytes(const uint8_t *in, size_t len, size_t *off,
		      uint8_t *out, size_t olen);
void *uudecode(const char *in, size_t len);
int uudecode_line(const char *in, size_t ilen, uint8_t *out, size_t *olen);

/* swap bytes in a 16 bit word */
uint16_t byteswap16(const uint16_t word);
uint32_t byteswap32(const uint32_t word);

/* process a text file, line by line */
int file_lines(const char *filename, int (*func)(char *, void *), void *param);

#endif /* __UTILS_H */
