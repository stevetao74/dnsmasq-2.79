/* dnsmasq is Copyright (c) 2000-2018 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
      
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* The SURF random number generator was taken from djbdns-1.05, by 
   Daniel J Bernstein, which is public domain. */


#include "dnsmasq.h"

static struct ubus_context *ctx = NULL;
static struct ap_laninfo arr_laninfo[64] = {0};

#ifdef HAVE_BROKEN_RTC
#include <sys/times.h>
#endif

#if defined(HAVE_LIBIDN2)
#include <idn2.h>
#elif defined(HAVE_IDN)
#include <idna.h>
#endif

/* SURF random number generator */

static u32 seed[32];
static u32 in[12];
static u32 out[8];
static int outleft = 0;

void rand_init()
{
  int fd = open(RANDFILE, O_RDONLY);
  
  if (fd == -1 ||
      !read_write(fd, (unsigned char *)&seed, sizeof(seed), 1) ||
      !read_write(fd, (unsigned char *)&in, sizeof(in), 1))
    die(_("failed to seed the random number generator: %s"), NULL, EC_MISC);
  
  close(fd);
}

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  u32 t[12]; u32 x; u32 sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

unsigned short rand16(void)
{
  if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return (unsigned short) out[--outleft];
}

u32 rand32(void)
{
 if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return out[--outleft]; 
}

u64 rand64(void)
{
  static int outleft = 0;

  if (outleft < 2)
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  outleft -= 2;

  return (u64)out[outleft+1] + (((u64)out[outleft]) << 32);
}

/* returns 2 if names is OK but contains one or more underscores */
static int check_name(char *in)
{
  /* remove trailing . 
     also fail empty string and label > 63 chars */
  size_t dotgap = 0, l = strlen(in);
  char c;
  int nowhite = 0;
  int hasuscore = 0;
  
  if (l == 0 || l > MAXDNAME) return 0;
  
  if (in[l-1] == '.')
    {
      in[l-1] = 0;
      nowhite = 1;
    }

  for (; (c = *in); in++)
    {
      if (c == '.')
	dotgap = 0;
      else if (++dotgap > MAXLABEL)
	return 0;
      else if (isascii((unsigned char)c) && iscntrl((unsigned char)c)) 
	/* iscntrl only gives expected results for ascii */
	return 0;
#if !defined(HAVE_IDN) && !defined(HAVE_LIBIDN2)
      else if (!isascii((unsigned char)c))
	return 0;
#endif
      else if (c != ' ')
	{
	  nowhite = 1;
	  if (c == '_')
	    hasuscore = 1;
	}
    }

  if (!nowhite)
    return 0;

  return hasuscore ? 2 : 1;
}

/* Hostnames have a more limited valid charset than domain names
   so check for legal char a-z A-Z 0-9 - _ 
   Note that this may receive a FQDN, so only check the first label 
   for the tighter criteria. */
int legal_hostname(char *name)
{
  char c;
  int first;

  if (!check_name(name))
    return 0;

  for (first = 1; (c = *name); name++, first = 0)
    /* check for legal char a-z A-Z 0-9 - _ . */
    {
      if ((c >= 'A' && c <= 'Z') ||
	  (c >= 'a' && c <= 'z') ||
	  (c >= '0' && c <= '9'))
	continue;

      if (!first && (c == '-' || c == '_'))
	continue;
      
      /* end of hostname part */
      if (c == '.')
	return 1;
      
      return 0;
    }
  
  return 1;
}
  
char *canonicalise(char *in, int *nomem)
{
  char *ret = NULL;
  int rc;
  
  if (nomem)
    *nomem = 0;
  
  if (!(rc = check_name(in)))
    return NULL;
  
#if defined(HAVE_LIBIDN2) && (!defined(IDN2_VERSION_NUMBER) || IDN2_VERSION_NUMBER < 0x02000003)
  /* older libidn2 strips underscores, so don't do IDN processing
     if the name has an underscore (check_name() returned 2) */
  if (rc != 2)
#endif
#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2)
    {
#  ifdef HAVE_LIBIDN2
      rc = idn2_to_ascii_lz(in, &ret, IDN2_NONTRANSITIONAL);
      if (rc == IDN2_DISALLOWED)
	rc = idn2_to_ascii_lz(in, &ret, IDN2_TRANSITIONAL);
#  else
      rc = idna_to_ascii_lz(in, &ret, 0);
#  endif
      if (rc != IDNA_SUCCESS)
	{
	  if (ret)
	    free(ret);
	  
	  if (nomem && (rc == IDNA_MALLOC_ERROR || rc == IDNA_DLOPEN_ERROR))
	    {
	      my_syslog(LOG_ERR, _("failed to allocate memory"));
	      *nomem = 1;
	    }
	  
	  return NULL;
	}
      
      return ret;
    }
#endif
  
  if ((ret = whine_malloc(strlen(in)+1)))
    strcpy(ret, in);
  else if (nomem)
    *nomem = 1;    

  return ret;
}

unsigned char *do_rfc1035_name(unsigned char *p, char *sval, char *limit)
{
  int j;
  
  while (sval && *sval)
    {
      unsigned char *cp = p++;

      if (limit && p > (unsigned char*)limit)
        return NULL;

      for (j = 0; *sval && (*sval != '.'); sval++, j++)
	{
          if (limit && p + 1 > (unsigned char*)limit)
            return NULL;

#ifdef HAVE_DNSSEC
	  if (option_bool(OPT_DNSSEC_VALID) && *sval == NAME_ESCAPE)
	    *p++ = (*(++sval))-1;
	  else
#endif		
	    *p++ = *sval;
	}
      
      *cp  = j;
      if (*sval)
	sval++;
    }
  
  return p;
}

/* for use during startup */
void *safe_malloc(size_t size)
{
  void *ret = calloc(1, size);
  
  if (!ret)
    die(_("could not get memory"), NULL, EC_NOMEM);
      
  return ret;
}    

void safe_pipe(int *fd, int read_noblock)
{
  if (pipe(fd) == -1 || 
      !fix_fd(fd[1]) ||
      (read_noblock && !fix_fd(fd[0])))
    die(_("cannot create pipe: %s"), NULL, EC_MISC);
}

void *whine_malloc(size_t size)
{
  void *ret = calloc(1, size);

  if (!ret)
    my_syslog(LOG_ERR, _("failed to allocate %d bytes"), (int) size);
  
  return ret;
}

int sockaddr_isequal(union mysockaddr *s1, union mysockaddr *s2)
{
  if (s1->sa.sa_family == s2->sa.sa_family)
    { 
      if (s1->sa.sa_family == AF_INET &&
	  s1->in.sin_port == s2->in.sin_port &&
	  s1->in.sin_addr.s_addr == s2->in.sin_addr.s_addr)
	return 1;
#ifdef HAVE_IPV6      
      if (s1->sa.sa_family == AF_INET6 &&
	  s1->in6.sin6_port == s2->in6.sin6_port &&
	  s1->in6.sin6_scope_id == s2->in6.sin6_scope_id &&
	  IN6_ARE_ADDR_EQUAL(&s1->in6.sin6_addr, &s2->in6.sin6_addr))
	return 1;
#endif
    }
  return 0;
}

int sa_len(union mysockaddr *addr)
{
#ifdef HAVE_SOCKADDR_SA_LEN
  return addr->sa.sa_len;
#else
#ifdef HAVE_IPV6
  if (addr->sa.sa_family == AF_INET6)
    return sizeof(addr->in6);
  else
#endif
    return sizeof(addr->in); 
#endif
}

/* don't use strcasecmp and friends here - they may be messed up by LOCALE */
int hostname_isequal(const char *a, const char *b)
{
  unsigned int c1, c2;
  
  do {
    c1 = (unsigned char) *a++;
    c2 = (unsigned char) *b++;
    
    if (c1 >= 'A' && c1 <= 'Z')
      c1 += 'a' - 'A';
    if (c2 >= 'A' && c2 <= 'Z')
      c2 += 'a' - 'A';
    
    if (c1 != c2)
      return 0;
  } while (c1);
  
  return 1;
}

time_t dnsmasq_time(void)
{
#ifdef HAVE_BROKEN_RTC
  struct tms dummy;
  static long tps = 0;

  if (tps == 0)
    tps = sysconf(_SC_CLK_TCK);

  return (time_t)(times(&dummy)/tps);
#else
  return time(NULL);
#endif
}

int netmask_length(struct in_addr mask)
{
  int zero_count = 0;

  while (0x0 == (mask.s_addr & 0x1) && zero_count < 32) 
    {
      mask.s_addr >>= 1;
      zero_count++;
    }
  
  return 32 - zero_count;
}

int is_same_net(struct in_addr a, struct in_addr b, struct in_addr mask)
{
  return (a.s_addr & mask.s_addr) == (b.s_addr & mask.s_addr);
} 

#ifdef HAVE_IPV6
int is_same_net6(struct in6_addr *a, struct in6_addr *b, int prefixlen)
{
  int pfbytes = prefixlen >> 3;
  int pfbits = prefixlen & 7;

  if (memcmp(&a->s6_addr, &b->s6_addr, pfbytes) != 0)
    return 0;

  if (pfbits == 0 ||
      (a->s6_addr[pfbytes] >> (8 - pfbits) == b->s6_addr[pfbytes] >> (8 - pfbits)))
    return 1;

  return 0;
}

/* return least significant 64 bits if IPv6 address */
u64 addr6part(struct in6_addr *addr)
{
  int i;
  u64 ret = 0;

  for (i = 8; i < 16; i++)
    ret = (ret << 8) + addr->s6_addr[i];

  return ret;
}

void setaddr6part(struct in6_addr *addr, u64 host)
{
  int i;

  for (i = 15; i >= 8; i--)
    {
      addr->s6_addr[i] = host;
      host = host >> 8;
    }
}

#endif
 

/* returns port number from address */
int prettyprint_addr(union mysockaddr *addr, char *buf)
{
  int port = 0;
  
#ifdef HAVE_IPV6
  if (addr->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &addr->in.sin_addr, buf, ADDRSTRLEN);
      port = ntohs(addr->in.sin_port);
    }
  else if (addr->sa.sa_family == AF_INET6)
    {
      char name[IF_NAMESIZE];
      inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, ADDRSTRLEN);
      if (addr->in6.sin6_scope_id != 0 &&
	  if_indextoname(addr->in6.sin6_scope_id, name) &&
	  strlen(buf) + strlen(name) + 2 <= ADDRSTRLEN)
	{
	  strcat(buf, "%");
	  strcat(buf, name);
	}
      port = ntohs(addr->in6.sin6_port);
    }
#else
  strcpy(buf, inet_ntoa(addr->in.sin_addr));
  port = ntohs(addr->in.sin_port); 
#endif
  
  return port;
}

void prettyprint_time(char *buf, unsigned int t)
{
  if (t == 0xffffffff)
    sprintf(buf, _("infinite"));
  else
    {
      unsigned int x, p = 0;
       if ((x = t/86400))
	p += sprintf(&buf[p], "%ud", x);
       if ((x = (t/3600)%24))
	p += sprintf(&buf[p], "%uh", x);
      if ((x = (t/60)%60))
	p += sprintf(&buf[p], "%um", x);
      if ((x = t%60))
	p += sprintf(&buf[p], "%us", x);
    }
}


/* in may equal out, when maxlen may be -1 (No max len). 
   Return -1 for extraneous no-hex chars found. */
int parse_hex(char *in, unsigned char *out, int maxlen, 
	      unsigned int *wildcard_mask, int *mac_type)
{
  int mask = 0, i = 0;
  char *r;
    
  if (mac_type)
    *mac_type = 0;
  
  while (maxlen == -1 || i < maxlen)
    {
      for (r = in; *r != 0 && *r != ':' && *r != '-' && *r != ' '; r++)
	if (*r != '*' && !isxdigit((unsigned char)*r))
	  return -1;
      
      if (*r == 0)
	maxlen = i;
      
      if (r != in )
	{
	  if (*r == '-' && i == 0 && mac_type)
	   {
	      *r = 0;
	      *mac_type = strtol(in, NULL, 16);
	      mac_type = NULL;
	   }
	  else
	    {
	      *r = 0;
	      if (strcmp(in, "*") == 0)
		{
		  mask = (mask << 1) | 1;
		  i++;
		}
	      else
		{
		  int j, bytes = (1 + (r - in))/2;
		  for (j = 0; j < bytes; j++)
		    { 
		      char sav = sav;
		      if (j < bytes - 1)
			{
			  sav = in[(j+1)*2];
			  in[(j+1)*2] = 0;
			}
		      /* checks above allow mix of hexdigit and *, which
			 is illegal. */
		      if (strchr(&in[j*2], '*'))
			return -1;
		      out[i] = strtol(&in[j*2], NULL, 16);
		      mask = mask << 1;
		      if (++i == maxlen)
			break; 
		      if (j < bytes - 1)
			in[(j+1)*2] = sav;
		    }
		}
	    }
	}
      in = r+1;
    }
  
  if (wildcard_mask)
    *wildcard_mask = mask;

  return i;
}

/* return 0 for no match, or (no matched octets) + 1 */
int memcmp_masked(unsigned char *a, unsigned char *b, int len, unsigned int mask)
{
  int i, count;
  for (count = 1, i = len - 1; i >= 0; i--, mask = mask >> 1)
    if (!(mask & 1))
      {
	if (a[i] == b[i])
	  count++;
	else
	  return 0;
      }
  return count;
}

/* _note_ may copy buffer */
int expand_buf(struct iovec *iov, size_t size)
{
  void *new;

  if (size <= (size_t)iov->iov_len)
    return 1;

  if (!(new = whine_malloc(size)))
    {
      errno = ENOMEM;
      return 0;
    }

  if (iov->iov_base)
    {
      memcpy(new, iov->iov_base, iov->iov_len);
      free(iov->iov_base);
    }

  iov->iov_base = new;
  iov->iov_len = size;

  return 1;
}

char *print_mac(char *buff, unsigned char *mac, int len)
{
  char *p = buff;
  int i;
   
  if (len == 0)
    sprintf(p, "<null>");
  else
    for (i = 0; i < len; i++)
      p += sprintf(p, "%.2x%s", mac[i], (i == len - 1) ? "" : ":");
  
  return buff;
}

/* rc is return from sendto and friends.
   Return 1 if we should retry.
   Set errno to zero if we succeeded. */
int retry_send(ssize_t rc)
{
  static int retries = 0;
  struct timespec waiter;
  
  if (rc != -1)
    {
      retries = 0;
      errno = 0;
      return 0;
    }
  
  /* Linux kernels can return EAGAIN in perpetuity when calling
     sendmsg() and the relevant interface has gone. Here we loop
     retrying in EAGAIN for 1 second max, to avoid this hanging 
     dnsmasq. */

  if (errno == EAGAIN || errno == EWOULDBLOCK)
     {
       waiter.tv_sec = 0;
       waiter.tv_nsec = 10000;
       nanosleep(&waiter, NULL);
       if (retries++ < 1000)
	 return 1;
     }
  
  retries = 0;
  
  if (errno == EINTR)
    return 1;
  
  return 0;
}

int read_write(int fd, unsigned char *packet, int size, int rw)
{
  ssize_t n, done;
  
  for (done = 0; done < size; done += n)
    {
      do { 
	if (rw)
	  n = read(fd, &packet[done], (size_t)(size - done));
	else
	  n = write(fd, &packet[done], (size_t)(size - done));
	
	if (n == 0)
	  return 0;
	
      } while (retry_send(n) || errno == ENOMEM || errno == ENOBUFS);

      if (errno != 0)
	return 0;
    }
     
  return 1;
}

/* Basically match a string value against a wildcard pattern.  */
int wildcard_match(const char* wildcard, const char* match)
{
  while (*wildcard && *match)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
    }

  return *wildcard == *match;
}

/* The same but comparing a maximum of NUM characters, like strncmp.  */
int wildcard_matchn(const char* wildcard, const char* match, int num)
{
  while (*wildcard && *match && num)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
      --num;
    }

  return (!num) || (*wildcard == *match);
}

static const struct blobmsg_policy laninfo_array_policy[__LANINFO_ARRAY_MAX] = 
{
	{.name = "ctcapd.laninfo", .type = BLOBMSG_TYPE_ARRAY}
};

static struct blobmsg_policy laninfo_table_policy[64] = {0};

static const struct blobmsg_policy laninfo_policy[__LANINFO_MAX] = 
{
	{.name = "mac", .type = BLOBMSG_TYPE_STRING},
	{.name = "ipaddr", .type = BLOBMSG_TYPE_STRING},
};

char *_get_config(const char *fmt, ...)
{
	struct uci_context *c;
	struct uci_ptr p;
	struct uci_element *e;
	char a[1024];
	static char value[1024];

	memset(value, 0, sizeof(value));

	c = uci_alloc_context();

	if (c == NULL) {
		my_syslog(LOG_ERR, _("uci_alloc_context failed"));
		return value;
	}

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(a, sizeof(a), fmt, ap);
	va_end(ap);

	if (UCI_OK == uci_lookup_ptr(c, &p, a, true) && (p.flags & UCI_LOOKUP_COMPLETE)) {
		e = p.last;

		if (e->type == UCI_TYPE_SECTION) {
			if (p.s) {
				strlcpy(value, p.s->type, sizeof(value));

			}
		} else if (e->type == UCI_TYPE_OPTION) {
			if (p.o && p.o->type == UCI_TYPE_STRING) {
				strlcpy(value, p.o->v.string, sizeof(value));
			}
		}
	}

	uci_free_context(c);
	return value;
}

void _set_config(int type, const char *fmt, ...)
{
	struct uci_context *c;
	struct uci_ptr p;
	char a[1024] = {0};
	int ret = 0;

	c = uci_alloc_context();

	if (c == NULL) {
		my_syslog(LOG_ERR, _("uci_alloc_context failed"));
		return;
	}

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(a, sizeof(a), fmt, ap);
	va_end(ap);

	if (UCI_OK != uci_lookup_ptr(c, &p, a, true)) {
		goto err;
	}

	switch (type) {
		case UCI_SET:
			ret = uci_set(c, &p);
			break;

		case UCI_DEL:
			ret = uci_delete(c, &p);
			break;

		case UCI_ADD_LIST:
			ret = uci_add_list(c, &p);
			break;

		case UCI_DEL_LIST:
			ret = uci_del_list(c, &p);
			break;

		case UCI_COMMIT:
		default:
			break;
	}

	if (UCI_OK != ret) {
		goto err;
	}

	if ((UCI_COMMIT != type) && (UCI_OK != uci_save(c, p.p))) {
		goto err;
	}

	if (UCI_OK != uci_commit(c, &p.p, false)) {
		goto err;
	}

	uci_free_context(c);
	return;
err:
	uci_perror(c, a);
	uci_free_context(c);
}

int _get_section_num(const char *config, const char *section)
{
	struct uci_context *c;
	struct uci_package *p = NULL;
	struct uci_element *e = NULL;
	int num = 0;

	c = uci_alloc_context();

	if (c == NULL) {
		my_syslog(LOG_ERR, _("uci_alloc_context failed"));
		return num;
	}

	if (UCI_OK != uci_load(c, config, &p)) {
		uci_perror(c, section);
		uci_free_context(c);
		return num;
	}

	uci_foreach_element(&p->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (s->type != NULL && section != NULL)
		{
			if (strcmp(s->type, section) == 0) {
				num++;
			}
		}
	}

	uci_free_context(c);
	return num;
}

void _ubus_init()
{
	ctx = ubus_connect(NULL);

	if (!ctx) {
		die(_("ubus_connect failed"), NULL, EC_INIT_OFFSET);
		exit(-1);
	}
}

void _ubus_done()
{
	ubus_free(ctx);
}

static int split_timerange(char *timerange, char *arr_timerange[], char *arr_time[6])
{
	int i = 0;
	char *buftmp = NULL;
	int idx_time = 0;
	int idx_timerange = 0;

	arr_timerange[0] = strtok_r(timerange, ",", &buftmp);
	while (arr_timerange[idx_timerange])
	{
		if (idx_timerange > 2)
		{
			return -1;
		}
		idx_timerange++;
		arr_timerange[idx_timerange] = strtok_r(NULL, ",", &buftmp);
	}

	while (arr_timerange[i])
	{
		if (i > 3)
		{
			return -1;
		}

		arr_time[idx_time]=strtok_r(arr_timerange[i], "-", &buftmp);
		while (arr_time[idx_time])
		{
			idx_time++;
			arr_time[idx_time] = strtok_r(NULL, "-", &buftmp);
		}
		++i;
	}

	return 0;
}

static void init_server_rules(unsigned int tmpidx, struct server_rule *dns_filter_rules)
{
	int ret = 0;
	char tmpenable[4] = {'\0'}, *arr_timerange[3] = {NULL};

	dns_filter_rules->uci_idx = tmpidx;
	dns_filter_rules->blockedtimes = atoi(_get_config("ctcapd.@dns_filter[%d].blockedtimes", tmpidx));
	dns_filter_rules->idx = atoi(_get_config("ctcapd.@dns_filter[%d].idx", tmpidx));
	strlcpy(dns_filter_rules->mac, _get_config("ctcapd.@dns_filter[%d].mac", tmpidx), sizeof(dns_filter_rules->mac));
	dns_filter_rules->mode = atoi(_get_config("ctcapd.@dns_filter[%d].mode", tmpidx));
	dns_filter_rules->action = atoi(_get_config("ctcapd.@dns_filter[%d].action", tmpidx));
	strlcpy(dns_filter_rules->weekdays, _get_config("ctcapd.@dns_filter[%d].weekdays", tmpidx), sizeof(dns_filter_rules->weekdays));
	strlcpy(dns_filter_rules->name, _get_config("ctcapd.@dns_filter[%d].name", tmpidx), sizeof(dns_filter_rules->name));
	strlcpy(dns_filter_rules->hostnames, _get_config("ctcapd.@dns_filter[%d].hostnames", tmpidx), sizeof(dns_filter_rules->hostnames));
	strlcpy(tmpenable, _get_config("ctcapd.@dns_filter[%d].enable", tmpidx), sizeof tmpenable);
	strlcpy(dns_filter_rules->oritimerange, _get_config("ctcapd.@dns_filter[%d].timerange", tmpidx), sizeof dns_filter_rules->oritimerange);

	ret = split_timerange(dns_filter_rules->oritimerange, arr_timerange, dns_filter_rules->timerange);
	if (ret == -1)
	{
		memset(dns_filter_rules->timerange, 0, sizeof dns_filter_rules->timerange);
		my_syslog(LOG_WARNING, _("param timerange is invalid"));
	}

	if (strcmp(tmpenable, "yes") == 0)
	{
		if (dns_filter_rules->mac[0] == '\0')
		{
			if (daemon->server_rules == NULL)
			{
				daemon->server_rules = dns_filter_rules;
			}else{
				dns_filter_rules->next = daemon->server_rules->next;
				daemon->server_rules->next = dns_filter_rules;
			}
		}else{
			if (daemon->server_rules_mac == NULL)
			{
				daemon->server_rules_mac = dns_filter_rules;
			}else{
				dns_filter_rules->next = daemon->server_rules_mac->next;
				daemon->server_rules_mac->next = dns_filter_rules;
			}
		}
	}
}

void _init_filter_rules()
{
	char buff[30] = {0};
	char *endptr = NULL;
	FILE *fp = NULL;
	unsigned char is_found = 0;
	unsigned int ucicount = 0;
	struct server_rule *tmprule = NULL, *tmprulemac = NULL;

	daemon->dns_filter_rules = NULL;
	daemon->server_rules = NULL;
	daemon->server_rules_mac = NULL;
	daemon->is_ntp = 0;
	memset(&daemon->match_server_rule, 0, sizeof(struct server_rule));

	ucicount = _get_section_num("ctcapd", "dns_filter");
	daemon->dns_filter_rules = calloc(ucicount, sizeof(struct server_rule));

	for (size_t i = 0; i < ucicount; i++)
	{
		init_server_rules(i, daemon->dns_filter_rules + i);
	}

	for (size_t i = 0; i < sizeof(laninfo_table_policy) / sizeof(laninfo_table_policy[0]); ++i)
	{
		laninfo_table_policy[i].type = BLOBMSG_TYPE_TABLE;
	}
}

void _uninit_filter_rules()
{
	if (daemon->dns_filter_rules != NULL)
	{
		free(daemon->dns_filter_rules);
		daemon->dns_filter_rules = NULL;
	}
}

void _set_blockedtimes(struct server_rule *serverrule)
{
	_set_config(UCI_SET, "ctcapd.@dns_filter[%d].blockedtimes=%d", serverrule->uci_idx, serverrule->blockedtimes);
}

static uint16_t myblobmsg_namelen(const struct blobmsg_hdr *hdr)
{
	return be16_to_cpu(hdr->namelen);
}

static int myblobmsg_parse_array(const struct blobmsg_policy *policy, int policy_len,
			struct blob_attr **tb, void *data, unsigned int len)
{
	struct blob_attr *attr;
	int i = 0;

	memset(tb, 0, policy_len * sizeof(*tb));
	__blob_for_each_attr(attr, data, len) {
		if (policy[i].type != BLOBMSG_TYPE_UNSPEC &&
		    blob_id(attr) != policy[i].type)
			continue;

		if (!blobmsg_check_attr(attr, false))
			return -1;

		if (tb[i])
			continue;

		tb[i++] = attr;
		if (i == policy_len)
			break;
	}

	return 0;
}

static int myblobmsg_parse_table_laninfo(const struct blobmsg_policy *policy, int policy_len,
                  struct blob_attr **tb, void *data, unsigned int len)
{
	struct blob_attr *attr;
	int i = 0;

	memset(tb, 0, policy_len * sizeof(*tb));
	__blob_for_each_attr(attr, data, len) {
		if (policy[i].type != BLOBMSG_TYPE_UNSPEC &&
		    blob_id(attr) != policy[i].type)
			continue;

		if (!blobmsg_check_attr(attr, false))
			return -1;

		if (tb[i])
			continue;

		tb[i++] = attr;
		if (i == policy_len)
			break;
	}

	return 0;
}

static int myblobmsg_parse_laninfo(const struct blobmsg_policy *policy, int policy_len,
                  struct blob_attr **tb, void *data, unsigned int len)
{
	struct blobmsg_hdr *hdr;
	struct blob_attr *attr;
	uint8_t *pslen;
	int i;
	int flag;

	memset(tb, 0, policy_len * sizeof(*tb));
	pslen = alloca(policy_len);
	for (i = 0; i < policy_len; i++) {
		if (!policy[i].name)
			continue;

		pslen[i] = strlen(policy[i].name);
	}

	__blob_for_each_attr(attr, data, len) {
		hdr = blob_data(attr);
		for (i = 0; i < policy_len; i++) {
			if (!policy[i].name)
				continue;

			if (myblobmsg_namelen(hdr) != pslen[i])
				continue;

			if (!blobmsg_check_attr(attr, true))
				return -1;

			if (tb[i])
				continue;

			if (strcmp(policy[i].name, (char *) hdr->name) != 0)
				continue;

			if (policy[i].type != BLOBMSG_TYPE_UNSPEC &&
			    blob_id(attr) != policy[i].type) {
				return -1;
			}

			tb[i] = attr;
		}
	}

	return 0;
}

static void get_lan_info_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	size_t i = 0;
	struct blob_attr *blobarray[__LANINFO_ARRAY_MAX] = {NULL};
	struct blob_attr *blobtb[64] = {NULL};
	struct blob_attr *bloblaninfo[64][__LANINFO_MAX] = {NULL};

	if (myblobmsg_parse_array(laninfo_array_policy, ARRAY_SIZE(laninfo_array_policy), blobarray, blob_data(msg), blob_len(msg)) != 0) {
		my_syslog(LOG_WARNING, _("parse lan info table failed"));
		return;
	}

	if (myblobmsg_parse_table_laninfo(laninfo_table_policy, ARRAY_SIZE(laninfo_table_policy), blobtb, blobmsg_data(blobarray[LANINFO_ARRAY]), blobmsg_len(blobarray[LANINFO_ARRAY])) != 0) {
		my_syslog(LOG_WARNING, _("parse lan info array failed"));
		return;
	}

	memset(&arr_laninfo, 0, sizeof(arr_laninfo));
	while (blobtb[i] != NULL)
	{
		if (myblobmsg_parse_laninfo(laninfo_policy, ARRAY_SIZE(laninfo_policy), bloblaninfo[i], blobmsg_data(blobtb[i]), blobmsg_len(blobtb[i])) != 0) {
			my_syslog(LOG_WARNING, _("parse lan info failed"));
			return;
		}

		strlcpy(arr_laninfo[i].mac, blobmsg_get_string(bloblaninfo[i][LANINFO_MAC]), sizeof arr_laninfo[i].mac);
		strlcpy(arr_laninfo[i].ipaddr, blobmsg_get_string(bloblaninfo[i][LANINFO_IPADDR]), sizeof arr_laninfo[i].ipaddr);
		++i;
	}
}

int _get_lan_info()
{
	unsigned int id = 0;
	int ret = 0;

	ret = ubus_lookup_id(ctx, "ctcapd.laninfo", &id);
	if (ret != UBUS_STATUS_OK) {
		my_syslog(LOG_WARNING, _("lookup scan_prog failed"));
		return ret;
	}

	return ubus_invoke(ctx, id, "list", NULL, get_lan_info_cb, NULL, 600);
}

void _getdstmac(struct in_addr src_addr_4, char *bufmac)
{
	for (size_t i = 0; i < sizeof(arr_laninfo) / sizeof(arr_laninfo[0]) ; i++)
	{
		if (inet_addr(arr_laninfo[i].ipaddr) == src_addr_4.s_addr)
		{
			strlcpy(bufmac, arr_laninfo[i].mac, sizeof arr_laninfo);
		}
	}
}

static time_t str2time(char *str_time){
	struct tm stm;
	strptime(str_time, "%Y-%m-%d %H:%M:%S",&stm);

	time_t t = mktime(&stm);
	return t;
}

static int time_match(struct server_rule *tmprule)
{
	struct tm *p;
	char weekday[2] = {'\0'};
	int j = 0;
	int is_in_time = 0;
	time_t time1 = 0;
	time_t time2 = 0;
	time_t timenow = 0;
	char strtmfmt1[17] = {'\0'};
	char strtmfmt2[17] = {'\0'};
	char *tmp00 = NULL;

	timenow = time(NULL);
	p = gmtime(&timenow);

	if (p->tm_wday == 0)
	{
		sprintf(weekday, "%d", 7);
	}else
	{
		sprintf(weekday, "%d", p->tm_wday);
	}

	if (tmprule->weekdays[0] == '\0')
	{
		return -2;
	}else if (strstr(tmprule->weekdays, weekday) == NULL)
	{
		return -1;
	}else if (strstr(tmprule->weekdays, weekday) != NULL)
	{
		if (tmprule->timerange[0] == NULL)
		{
			return -2;
		}

		while (tmprule->timerange[j])
		{
			memset(strtmfmt1, '\0', sizeof(strtmfmt1));
			memset(strtmfmt2, '\0', sizeof(strtmfmt2));
			if (j % 2 == 0)
			{
				sprintf(strtmfmt1, "%04d-%02d-%02d %s:00", p->tm_year + 1900, p->tm_mon + 1, p->tm_mday, tmprule->timerange[j]);
				time1 = str2time(strtmfmt1);
				tmp00 = tmprule->timerange[j];
			}else if (j % 2 == 1){
				if (tmp00 && strncmp(tmp00, tmprule->timerange[j], strlen(tmp00)) == 0 && strncmp(tmp00, "00:00", strlen(tmp00)) == 0)
				{
					return 0;
				}

				sprintf(strtmfmt2, "%04d-%02d-%02d %s:00", p->tm_year + 1900, p->tm_mon + 1, p->tm_mday, tmprule->timerange[j]);
				time2 = str2time(strtmfmt2);
				if (timenow >= time1 && timenow <= time2)
				{
					is_in_time = 1;
				}
			}

			++j;
		}

		if (is_in_time == 1)
		{
			return 0;
		}
	}

	return -1;
}

static unsigned ntpstatus()
{
	struct tm *p = NULL;
	time_t timenow = 0;

	timenow = time(NULL);
	p = gmtime(&timenow);

	if (p != NULL)
		return p->tm_year > (2019 - 1900);
	
	return 0;
}

int _macth_rule_dnsfilter(struct in_addr src_addr_4)
{
	char tmpname[1025] = {0}, srcmac[18] = {'\0'}, *hostret = NULL;
	int timematching = 0, is_found = 0, dotret = 0;
	struct server_rule *tmprule = daemon->server_rules, *tmprulemac = daemon->server_rules_mac;

	if (!daemon->is_ntp)
	{
		daemon->is_ntp = ntpstatus();
	}

	if (!daemon->is_ntp)
	{
		return -1;
	}

	memset(&daemon->match_server_rule, 0, sizeof(struct server_rule));
	_getdstmac(src_addr_4, srcmac);

	strlcpy(tmpname, daemon->namebuff, sizeof tmpname);
	hostret = strrchr(tmpname, '.');
	if (hostret != NULL)
	{
		dotret = hostret - tmpname;
		tmpname[dotret] = '\0';
		hostret = strrchr(tmpname, '.');
		if (hostret != NULL)
		{
			dotret = hostret - tmpname;
			strlcpy(tmpname, daemon->namebuff + dotret + 1, sizeof tmpname);
		}else{
			strlcpy(tmpname, daemon->namebuff, sizeof tmpname);
		}
	}

	while (tmprulemac != NULL)
	{
		if (srcmac[0] == '\0')
		{
			break;
		}

		if (strncasecmp(srcmac, tmprulemac->mac, strlen(srcmac)) == 0)
		{
			timematching = time_match(tmprulemac);
			if(timematching == -2)
			{
				return -2;
			}else if (timematching == 0)
			{
				if (strstr(tmprulemac->hostnames, tmpname))
				{
					if (tmprulemac->mode == 0 && tmprulemac->action == 2)
					{
						tmprulemac->blockedtimes++;
					}
					memcpy(&daemon->match_server_rule, tmprulemac, sizeof(struct server_rule));
					return 0;
				}else if (is_found == 0){
					daemon->match_server_rule.uci_idx = tmprulemac->uci_idx;
					daemon->match_server_rule.mode = (tmprulemac->mode == 0 ? 1 : 0);
					daemon->match_server_rule.action = tmprulemac->action;
					if (daemon->match_server_rule.mode == 0 && daemon->match_server_rule.action == 2)
					{
						tmprulemac->blockedtimes++;
					}
					daemon->match_server_rule.blockedtimes = tmprulemac->blockedtimes;
					is_found = 1;
				}
			}
		}
		tmprulemac = tmprulemac->next;
	}

	while (tmprule != NULL)
	{
		timematching = time_match(tmprule);
		if (timematching == -2)
		{
			return -2;
		}else if(timematching == 0)
		{
			if(strstr(tmprule->hostnames, tmpname))
			{
				if (tmprule->mode == 0 && tmprule->action == 2)
				{
					tmprule->blockedtimes++;
				}
				memcpy(&daemon->match_server_rule, tmprule, sizeof(struct server_rule));
				return 0;
			}else if (is_found == 0){
				daemon->match_server_rule.uci_idx = tmprule->uci_idx;
				daemon->match_server_rule.mode = (tmprule->mode == 0 ? 1 : 0);
				daemon->match_server_rule.action = tmprule->action;
				if (daemon->match_server_rule.mode == 0 && daemon->match_server_rule.action == 2)
				{
					tmprule->blockedtimes++;
				}
				daemon->match_server_rule.blockedtimes = tmprule->blockedtimes;
				is_found = 1;
			}
		}
		tmprule = tmprule->next;
	}

	if (is_found == 1)
	{
		return 0;
	}

	return -1;

}

in_addr_t _find_lanip(char *interface_name)
{
 struct irec *tmpirec = NULL;
 for (tmpirec = daemon->interfaces; tmpirec; tmpirec = tmpirec->next)
 {
	 if (strncmp(tmpirec->name, interface_name, strlen(tmpirec->name)) == 0)
	 {
		 return tmpirec->addr.in.sin_addr.s_addr;
	 }
 }

 return 0;
}