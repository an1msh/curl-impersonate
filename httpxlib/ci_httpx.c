#include "ci_httpx.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <limits.h>
#include <netdb.h>
#include <regex.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CIHX_OK 0
#define CIHX_ERR_INVALID -1
#define CIHX_ERR_NOMEM -2
#define CIHX_ERR_CURL -3
#define CIHX_ERR_IO -4

#define CIHX_DEFAULT_TIMEOUT 10L
#define CIHX_DEFAULT_REDIRECTS 10L
#define CIHX_DEFAULT_BODY_PREVIEW 100u
#define CIHX_DEFAULT_MAX_BODY (10u * 1024u * 1024u)

struct strvec {
  char **items;
  size_t len;
  size_t cap;
};

struct buffer {
  char *data;
  size_t len;
  size_t cap;
  size_t limit;
  bool truncated;
};

struct header_block {
  char *url;
  char *request;
  size_t request_len;
  char *raw;
  size_t raw_len;
  long status;
  char *location;
  struct cihx_header *headers;
  size_t header_count;
  size_t header_cap;
};

struct capture {
  struct buffer body;
  struct buffer request;
  struct header_block *blocks;
  size_t block_count;
  size_t block_cap;
  char primary_ip[INET6_ADDRSTRLEN];
  char error[CURL_ERROR_SIZE];
};

struct intset {
  long *values;
  size_t len;
  size_t cap;
};

struct regexvec {
  regex_t *items;
  char **patterns;
  size_t len;
  size_t cap;
};

static void regexvec_free(struct regexvec *v);

struct time_expr {
  char op[3];
  double seconds;
  bool enabled;
};

struct port_spec {
  char *scheme;
  long port;
};

struct tech_signature {
  const char *name;
  const char *header_name;
  const char *header_contains;
  const char *body_contains;
};

struct cdn_header_signature {
  const char *name;
  const char *type;
  const char *header_name;
  const char *header_contains;
};

struct cdn_cidr_signature {
  const char *name;
  const char *type;
  const char *cidr;
};

struct result_owned {
  struct cihx_result pub;
  char *url;
  char *input;
  char *final_url;
  char *scheme;
  char *host;
  char *host_ip;
  char *port;
  char *path;
  char *method;
  char *location;
  char *title;
  char *webserver;
  char *content_type;
  char *body_preview;
  char *response_body;
  char *raw_header;
  char *request;
  char *error;
  char *cdn_name;
  char *cdn_type;
  char *tech;
  struct cihx_header *headers;
  struct cihx_chain_item *chain;
  long *chain_status_codes;
  struct cihx_extract_item *extracts;
};

struct cihx_options {
  struct strvec targets;
  struct strvec paths;
  struct strvec headers;
  struct strvec resolvers;
  struct strvec match_strings;
  struct strvec filter_strings;
  struct strvec match_cdn;
  struct strvec filter_cdn;
  struct strvec methods;
  bool methods_explicit;
  struct regexvec match_regexes;
  struct regexvec filter_regexes;
  struct regexvec extract_regexes;
  struct intset match_status;
  struct intset match_length;
  struct intset match_lines;
  struct intset match_words;
  struct intset filter_status;
  struct intset filter_length;
  struct intset filter_lines;
  struct intset filter_words;
  struct time_expr match_time;
  struct time_expr filter_time;
  struct port_spec *ports;
  size_t port_count;
  size_t port_cap;
  char *proxy;
  char *body;
  char *default_scheme;
  char *ports_expr;
  char *match_condition;
  char *filter_condition;
  FILE *json_output;
  unsigned int probe_flags;
  unsigned int extract_presets;
  size_t body_preview_size;
  size_t max_body_bytes;
  long max_redirects;
  long timeout_seconds;
  long retries;
  bool include_response_header;
  bool include_response;
  bool include_chain;
  bool follow_redirects;
  bool follow_host_redirects;
  bool no_fallback;
  bool no_fallback_scheme;
  bool random_agent;
  bool auto_referer;
  bool probe_all_ips;
};

static const char *const random_user_agents[] = {
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
  "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
};

static const struct tech_signature tech_signatures[] = {
  {"Nginx", "Server", "nginx", NULL},
  {"Apache HTTP Server", "Server", "apache", NULL},
  {"Microsoft IIS", "Server", "microsoft-iis", NULL},
  {"OpenResty", "Server", "openresty", NULL},
  {"Cloudflare", "Server", "cloudflare", NULL},
  {"PHP", "X-Powered-By", "php", NULL},
  {"Express", "X-Powered-By", "express", NULL},
  {"ASP.NET", "X-Powered-By", "asp.net", NULL},
  {"Next.js", "X-Powered-By", "next.js", NULL},
  {"WordPress", NULL, NULL, "wp-content"},
  {"WordPress", NULL, NULL, "wp-json"},
  {"Drupal", NULL, NULL, "drupal-settings-json"},
  {"Drupal", NULL, NULL, "/sites/default/files/"},
  {"Joomla", NULL, NULL, "content=\"joomla!"},
  {"jQuery", NULL, NULL, "jquery"},
  {"Bootstrap", NULL, NULL, "bootstrap.min.css"},
  {"Bootstrap", NULL, NULL, "bootstrap.min.js"},
  {"React", NULL, NULL, "react-dom"},
  {"Next.js", NULL, NULL, "__next_data__"},
  {"Vue.js", NULL, NULL, "vue.js"},
  {"Angular", NULL, NULL, "ng-version"}
};

static const struct cdn_header_signature cdn_header_signatures[] = {
  {"cloudflare", "cdn", "Server", "cloudflare"},
  {"cloudflare", "cdn", "CF-Ray", ""},
  {"cloudflare", "cdn", "CF-Cache-Status", ""},
  {"cloudfront", "cdn", "Server", "cloudfront"},
  {"cloudfront", "cdn", "X-Cache", "cloudfront"},
  {"cloudfront", "cdn", "X-Amz-Cf-Id", ""},
  {"fastly", "cdn", "Server", "fastly"},
  {"fastly", "cdn", "Fastly-Debug-Digest", ""},
  {"akamai", "cdn", "Server", "akamai"},
  {"akamai", "cdn", "Akamai-Cache-Status", ""},
  {"akamai", "cdn", "X-Akamai-Transformed", ""},
  {"google", "cdn", "Server", "gws"}
};

/*
 * Conservative built-in edge ranges.  The matcher is data-driven so these can
 * be expanded without touching the matching logic.  Header signatures remain a
 * fallback/augment because public CDN ranges change over time.
 */
static const struct cdn_cidr_signature cdn_cidr_signatures[] = {
  {"cloudflare", "cdn", "173.245.48.0/20"},
  {"cloudflare", "cdn", "103.21.244.0/22"},
  {"cloudflare", "cdn", "103.22.200.0/22"},
  {"cloudflare", "cdn", "103.31.4.0/22"},
  {"cloudflare", "cdn", "141.101.64.0/18"},
  {"cloudflare", "cdn", "108.162.192.0/18"},
  {"cloudflare", "cdn", "190.93.240.0/20"},
  {"cloudflare", "cdn", "188.114.96.0/20"},
  {"cloudflare", "cdn", "197.234.240.0/22"},
  {"cloudflare", "cdn", "198.41.128.0/17"},
  {"cloudflare", "cdn", "162.158.0.0/15"},
  {"cloudflare", "cdn", "104.16.0.0/13"},
  {"cloudflare", "cdn", "104.24.0.0/14"},
  {"cloudflare", "cdn", "172.64.0.0/13"},
  {"cloudflare", "cdn", "131.0.72.0/22"},
  {"cloudflare", "cdn", "2400:cb00::/32"},
  {"cloudflare", "cdn", "2606:4700::/32"},
  {"cloudflare", "cdn", "2803:f800::/32"},
  {"cloudflare", "cdn", "2405:b500::/32"},
  {"cloudflare", "cdn", "2405:8100::/32"},
  {"cloudflare", "cdn", "2a06:98c0::/29"},
  {"cloudflare", "cdn", "2c0f:f248::/32"},
  {"fastly", "cdn", "23.235.32.0/20"},
  {"fastly", "cdn", "43.249.72.0/22"},
  {"fastly", "cdn", "103.244.50.0/24"},
  {"fastly", "cdn", "146.75.0.0/16"},
  {"fastly", "cdn", "151.101.0.0/16"},
  {"fastly", "cdn", "199.27.72.0/21"},
  {"cloudfront", "cdn", "13.32.0.0/15"},
  {"cloudfront", "cdn", "13.224.0.0/14"},
  {"cloudfront", "cdn", "18.64.0.0/14"},
  {"cloudfront", "cdn", "54.230.0.0/16"},
  {"cloudfront", "cdn", "54.239.128.0/18"},
  {"cloudfront", "cdn", "99.84.0.0/16"},
  {"cloudfront", "cdn", "99.86.0.0/16"},
  {"cloudfront", "cdn", "143.204.0.0/16"},
  {"cloudfront", "cdn", "205.251.192.0/19"},
  {"akamai", "cdn", "2.16.0.0/13"},
  {"akamai", "cdn", "23.32.0.0/11"},
  {"akamai", "cdn", "23.192.0.0/11"},
  {"akamai", "cdn", "95.100.0.0/15"},
  {"akamai", "cdn", "104.64.0.0/10"},
  {"akamai", "cdn", "184.24.0.0/13"},
  {"akamai", "cdn", "184.50.0.0/15"}
};

static void *xcalloc(size_t n, size_t size)
{
  if(size && n > SIZE_MAX / size)
    return NULL;
  return calloc(n, size);
}

static char *xstrdup(const char *s)
{
  size_t len;
  char *out;

  if(!s)
    return NULL;
  len = strlen(s);
  out = malloc(len + 1);
  if(!out)
    return NULL;
  memcpy(out, s, len + 1);
  return out;
}

static char *xstrndup(const char *s, size_t len)
{
  char *out = malloc(len + 1);
  if(!out)
    return NULL;
  memcpy(out, s, len);
  out[len] = 0;
  return out;
}

static char *trim_in_place(char *s)
{
  char *end;

  while(*s && isspace((unsigned char)*s))
    s++;
  end = s + strlen(s);
  while(end > s && isspace((unsigned char)end[-1]))
    *--end = 0;
  return s;
}

static bool is_blank_or_comment(const char *s)
{
  while(*s && isspace((unsigned char)*s))
    s++;
  return *s == 0 || *s == '#';
}

static bool csv_has_empty_item(const char *s)
{
  const char *item = s;

  if(!s)
    return true;
  for(;;) {
    const char *comma = strchr(item, ',');
    const char *end = comma ? comma : item + strlen(item);
    const char *left = item;
    const char *right = end;

    while(left < right && isspace((unsigned char)*left))
      left++;
    while(right > left && isspace((unsigned char)right[-1]))
      right--;
    if(left == right)
      return true;
    if(!comma)
      return false;
    item = comma + 1;
  }
}

static int strvec_push(struct strvec *v, const char *value)
{
  char **next;
  char *copy;
  size_t cap;

  if(!value)
    return CIHX_ERR_INVALID;
  copy = xstrdup(value);
  if(!copy)
    return CIHX_ERR_NOMEM;
  if(v->len == v->cap) {
    cap = v->cap ? v->cap * 2 : 8;
    next = realloc(v->items, cap * sizeof(*next));
    if(!next) {
      free(copy);
      return CIHX_ERR_NOMEM;
    }
    v->items = next;
    v->cap = cap;
  }
  v->items[v->len++] = copy;
  return CIHX_OK;
}

static int strvec_push_trimmed(struct strvec *v, const char *value)
{
  char *copy;
  char *trimmed;
  int rc;

  if(!value)
    return CIHX_ERR_INVALID;
  copy = xstrdup(value);
  if(!copy)
    return CIHX_ERR_NOMEM;
  trimmed = trim_in_place(copy);
  rc = *trimmed ? strvec_push(v, trimmed) : CIHX_OK;
  free(copy);
  return rc;
}

static void strvec_free(struct strvec *v)
{
  size_t i;
  for(i = 0; i < v->len; i++)
    free(v->items[i]);
  free(v->items);
  memset(v, 0, sizeof(*v));
}

static int strvec_clone(struct strvec *dst, const struct strvec *src)
{
  size_t i;
  int rc;

  memset(dst, 0, sizeof(*dst));
  for(i = 0; i < src->len; i++) {
    rc = strvec_push(dst, src->items[i]);
    if(rc) {
      strvec_free(dst);
      return rc;
    }
  }
  return CIHX_OK;
}

static int strvec_extend_move(struct strvec *dst, struct strvec *src)
{
  char **next;
  size_t needed;
  size_t cap;

  if(!src->len)
    return CIHX_OK;
  if(dst->len > SIZE_MAX - src->len)
    return CIHX_ERR_NOMEM;
  needed = dst->len + src->len;
  if(needed > dst->cap) {
    cap = dst->cap ? dst->cap : 8;
    while(cap < needed) {
      if(cap > SIZE_MAX / 2)
        return CIHX_ERR_NOMEM;
      cap *= 2;
    }
    next = realloc(dst->items, cap * sizeof(*next));
    if(!next)
      return CIHX_ERR_NOMEM;
    dst->items = next;
    dst->cap = cap;
  }
  memcpy(dst->items + dst->len, src->items, src->len * sizeof(*src->items));
  dst->len += src->len;
  free(src->items);
  memset(src, 0, sizeof(*src));
  return CIHX_OK;
}

static int buffer_appendn(struct buffer *b, const char *data, size_t len);

static bool strvec_contains_ci(const struct strvec *v, const char *value)
{
  size_t i;
  if(!value)
    return false;
  for(i = 0; i < v->len; i++) {
    if(!strcasecmp(v->items[i], value))
      return true;
  }
  return false;
}

static bool strvec_contains(const struct strvec *v, const char *value)
{
  size_t i;
  if(!value)
    return false;
  for(i = 0; i < v->len; i++) {
    if(!strcmp(v->items[i], value))
      return true;
  }
  return false;
}

static bool header_name_matches(const char *header, const char *name)
{
  size_t name_len;
  const char *colon;

  if(!header || !name)
    return false;
  colon = strchr(header, ':');
  if(!colon)
    return false;
  name_len = strlen(name);
  while(colon > header && isspace((unsigned char)colon[-1]))
    colon--;
  return (size_t)(colon - header) == name_len &&
         !strncasecmp(header, name, name_len);
}

static bool headers_include_name(const struct strvec *headers, const char *name)
{
  size_t i;

  for(i = 0; i < headers->len; i++) {
    if(header_name_matches(headers->items[i], name))
      return true;
  }
  return false;
}

static char *strvec_join(const struct strvec *v, const char *sep)
{
  struct buffer out = {0};
  size_t i;

  for(i = 0; i < v->len; i++) {
    if(i)
      (void)buffer_appendn(&out, sep, strlen(sep));
    (void)buffer_appendn(&out, v->items[i], strlen(v->items[i]));
  }
  return out.data;
}

static int buffer_appendn(struct buffer *b, const char *data, size_t len)
{
  char *next;
  size_t needed;
  size_t cap;

  if(!len)
    return CIHX_OK;
  if(b->limit && b->len + len > b->limit) {
    if(b->len >= b->limit) {
      b->truncated = true;
      return CIHX_OK;
    }
    len = b->limit - b->len;
    b->truncated = true;
  }
  needed = b->len + len + 1;
  if(needed < b->len)
    return CIHX_ERR_NOMEM;
  if(needed > b->cap) {
    cap = b->cap ? b->cap * 2 : 4096;
    while(cap < needed) {
      if(cap > SIZE_MAX / 2)
        return CIHX_ERR_NOMEM;
      cap *= 2;
    }
    next = realloc(b->data, cap);
    if(!next)
      return CIHX_ERR_NOMEM;
    b->data = next;
    b->cap = cap;
  }
  memcpy(b->data + b->len, data, len);
  b->len += len;
  b->data[b->len] = 0;
  return CIHX_OK;
}

static int buffer_appendf(struct buffer *b, const char *fmt, ...)
{
  char stack[512];
  char *heap = NULL;
  va_list ap;
  va_list ap2;
  int n;
  int rc;

  va_start(ap, fmt);
  va_copy(ap2, ap);
  n = vsnprintf(stack, sizeof(stack), fmt, ap);
  va_end(ap);
  if(n < 0) {
    va_end(ap2);
    return CIHX_ERR_INVALID;
  }
  if((size_t)n < sizeof(stack)) {
    va_end(ap2);
    return buffer_appendn(b, stack, (size_t)n);
  }
  heap = malloc((size_t)n + 1);
  if(!heap) {
    va_end(ap2);
    return CIHX_ERR_NOMEM;
  }
  vsnprintf(heap, (size_t)n + 1, fmt, ap2);
  va_end(ap2);
  rc = buffer_appendn(b, heap, (size_t)n);
  free(heap);
  return rc;
}

static void buffer_free(struct buffer *b)
{
  free(b->data);
  memset(b, 0, sizeof(*b));
}

static int intset_push(struct intset *set, long value)
{
  long *next;
  size_t cap;
  size_t i;

  for(i = 0; i < set->len; i++) {
    if(set->values[i] == value)
      return CIHX_OK;
  }
  if(set->len == set->cap) {
    cap = set->cap ? set->cap * 2 : 8;
    next = realloc(set->values, cap * sizeof(*next));
    if(!next)
      return CIHX_ERR_NOMEM;
    set->values = next;
    set->cap = cap;
  }
  set->values[set->len++] = value;
  return CIHX_OK;
}

static void intset_free(struct intset *set)
{
  free(set->values);
  memset(set, 0, sizeof(*set));
}

static bool intset_contains(const struct intset *set, long value)
{
  size_t i;
  for(i = 0; i < set->len; i++) {
    if(set->values[i] == value)
      return true;
  }
  return false;
}

static int parse_number_list(const char *expr, struct intset *out)
{
  char *copy;
  char *tok;
  char *save = NULL;
  int rc = CIHX_OK;

  if(!expr || !*expr)
    return CIHX_OK;
  if(csv_has_empty_item(expr))
    return CIHX_ERR_INVALID;
  copy = xstrdup(expr);
  if(!copy)
    return CIHX_ERR_NOMEM;
  for(tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
    char *s = trim_in_place(tok);
    char *dash;
    char *end = NULL;
    long a;
    long b;
    long n;

    if(!*s)
      continue;
    dash = strchr(s, '-');
    errno = 0;
    a = strtol(s, &end, 10);
    if(errno || end == s) {
      rc = CIHX_ERR_INVALID;
      break;
    }
    if(dash) {
      char *end2 = NULL;
      errno = 0;
      b = strtol(dash + 1, &end2, 10);
      if(errno || end2 == dash + 1 || *trim_in_place(end2) || b < a) {
        rc = CIHX_ERR_INVALID;
        break;
      }
      for(n = a; n <= b; n++) {
        rc = intset_push(out, n);
        if(rc)
          break;
        if(n == LONG_MAX)
          break;
      }
    }
    else {
      if(*trim_in_place(end)) {
        rc = CIHX_ERR_INVALID;
        break;
      }
      rc = intset_push(out, a);
    }
    if(rc)
      break;
  }
  free(copy);
  return rc;
}

static int parse_time_expr(const char *expr, struct time_expr *out)
{
  static const char *ops[] = {">=", "<=", "!=", ">", "<", "="};
  char *end = NULL;
  size_t i;
  double value;

  memset(out, 0, sizeof(*out));
  if(!expr || !*expr)
    return CIHX_OK;
  while(*expr && isspace((unsigned char)*expr))
    expr++;
  for(i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
    size_t oplen = strlen(ops[i]);
    if(!strncmp(expr, ops[i], oplen)) {
      strncpy(out->op, ops[i], sizeof(out->op) - 1);
      expr += oplen;
      break;
    }
  }
  if(!out->op[0])
    return CIHX_ERR_INVALID;
  while(*expr && isspace((unsigned char)*expr))
    expr++;
  errno = 0;
  value = strtod(expr, &end);
  if(errno || end == expr)
    return CIHX_ERR_INVALID;
  while(*end && isspace((unsigned char)*end))
    end++;
  if(!strncasecmp(end, "ns", 2)) {
    value /= 1000000000.0;
    end += 2;
  }
  else if(!strncasecmp(end, "us", 2)) {
    value /= 1000000.0;
    end += 2;
  }
  else if(!strncasecmp(end, "ms", 2)) {
    value /= 1000.0;
    end += 2;
  }
  else if(*end == 's') {
    end++;
  }
  else if(*end == 'm') {
    value *= 60.0;
    end++;
  }
  else if(*end == 'h') {
    value *= 3600.0;
    end++;
  }
  while(*end && isspace((unsigned char)*end))
    end++;
  if(*end)
    return CIHX_ERR_INVALID;
  out->seconds = value;
  out->enabled = true;
  return CIHX_OK;
}

static bool time_expr_matches(const struct time_expr *expr, double value)
{
  if(!expr->enabled)
    return true;
  if(!strcmp(expr->op, ">="))
    return value >= expr->seconds;
  if(!strcmp(expr->op, "<="))
    return value <= expr->seconds;
  if(!strcmp(expr->op, ">"))
    return value > expr->seconds;
  if(!strcmp(expr->op, "<"))
    return value < expr->seconds;
  if(!strcmp(expr->op, "="))
    return value == expr->seconds;
  if(!strcmp(expr->op, "!="))
    return value != expr->seconds;
  return false;
}

static int regexvec_add(struct regexvec *v, const char *pattern)
{
  regex_t rx;
  regex_t *next_rx;
  char **next_patterns;
  size_t cap;
  int err;

  if(!pattern || !*pattern)
    return CIHX_ERR_INVALID;
  err = regcomp(&rx, pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE);
  if(err)
    return CIHX_ERR_INVALID;
  if(v->len == v->cap) {
    cap = v->cap ? v->cap * 2 : 4;
    next_rx = realloc(v->items, cap * sizeof(*next_rx));
    if(!next_rx) {
      regfree(&rx);
      return CIHX_ERR_NOMEM;
    }
    v->items = next_rx;
    next_patterns = realloc(v->patterns, cap * sizeof(*next_patterns));
    if(!next_patterns) {
      regfree(&rx);
      return CIHX_ERR_NOMEM;
    }
    v->patterns = next_patterns;
    v->cap = cap;
  }
  v->patterns[v->len] = xstrdup(pattern);
  if(!v->patterns[v->len]) {
    regfree(&rx);
    return CIHX_ERR_NOMEM;
  }
  v->items[v->len++] = rx;
  return CIHX_OK;
}

static int regexvec_extend_move(struct regexvec *dst, struct regexvec *src)
{
  regex_t *next_items;
  char **next_patterns;
  size_t needed;
  size_t cap;

  if(!src->len)
    return CIHX_OK;
  if(dst->len > SIZE_MAX - src->len)
    return CIHX_ERR_NOMEM;
  needed = dst->len + src->len;
  if(needed > dst->cap) {
    cap = dst->cap ? dst->cap : 4;
    while(cap < needed) {
      if(cap > SIZE_MAX / 2)
        return CIHX_ERR_NOMEM;
      cap *= 2;
    }
    next_items = realloc(dst->items, cap * sizeof(*next_items));
    if(!next_items)
      return CIHX_ERR_NOMEM;
    dst->items = next_items;
    next_patterns = realloc(dst->patterns, cap * sizeof(*next_patterns));
    if(!next_patterns)
      return CIHX_ERR_NOMEM;
    dst->patterns = next_patterns;
    dst->cap = cap;
  }
  memcpy(dst->items + dst->len, src->items, src->len * sizeof(*src->items));
  memcpy(dst->patterns + dst->len, src->patterns,
         src->len * sizeof(*src->patterns));
  dst->len += src->len;
  free(src->items);
  free(src->patterns);
  memset(src, 0, sizeof(*src));
  return CIHX_OK;
}

static int regexvec_add_csv(struct regexvec *out, const char *value)
{
  char *copy;
  char *cursor;
  struct regexvec parsed = {0};
  int rc = CIHX_OK;

  if(!value)
    return CIHX_ERR_INVALID;
  copy = xstrdup(value);
  if(!copy)
    return CIHX_ERR_NOMEM;
  cursor = copy;
  for(;;) {
    char *comma = strchr(cursor, ',');
    char *trimmed;
    if(comma)
      *comma = 0;
    trimmed = trim_in_place(cursor);
    if(!*trimmed) {
      rc = CIHX_ERR_INVALID;
      break;
    }
    rc = regexvec_add(&parsed, trimmed);
    if(rc)
      break;
    if(!comma)
      break;
    cursor = comma + 1;
  }
  free(copy);
  if(!rc)
    rc = regexvec_extend_move(out, &parsed);
  regexvec_free(&parsed);
  return rc;
}

static void regexvec_free(struct regexvec *v)
{
  size_t i;
  for(i = 0; i < v->len; i++) {
    regfree(&v->items[i]);
    free(v->patterns[i]);
  }
  free(v->items);
  free(v->patterns);
  memset(v, 0, sizeof(*v));
}

static int read_lines_into(const char *path, struct strvec *out)
{
  FILE *fp;
  struct buffer line = {0};
  int rc = CIHX_OK;

  fp = fopen(path, "r");
  if(!fp)
    return CIHX_ERR_IO;
  for(;;) {
    int ch;
    bool got_line = false;

    line.len = 0;
    if(line.data)
      line.data[0] = 0;
    while((ch = fgetc(fp)) != EOF) {
      char c = (char)ch;
      got_line = true;
      rc = buffer_appendn(&line, &c, 1);
      if(rc)
        break;
      if(c == '\n')
        break;
    }
    if(rc)
      break;
    if(ferror(fp)) {
      rc = CIHX_ERR_IO;
      break;
    }
    if(!got_line)
      break;
    {
      char *s = trim_in_place(line.data ? line.data : "");
      if(!is_blank_or_comment(s)) {
        rc = strvec_push(out, s);
        if(rc)
          break;
      }
    }
  }
  buffer_free(&line);
  fclose(fp);
  return rc;
}

static bool looks_like_file(const char *s)
{
  struct stat st;
  if(!s || strchr(s, ','))
    return false;
  if(stat(s, &st))
    return false;
  return S_ISREG(st.st_mode);
}

static int add_csv_values(struct strvec *out, const char *value)
{
  char *copy;
  char *cursor;
  struct strvec parsed = {0};
  int rc = CIHX_OK;

  if(!value)
    return CIHX_ERR_INVALID;
  copy = xstrdup(value);
  if(!copy)
    return CIHX_ERR_NOMEM;
  cursor = copy;
  for(;;) {
    char *comma = strchr(cursor, ',');
    char *trimmed;
    if(comma)
      *comma = 0;
    trimmed = trim_in_place(cursor);
    if(!*trimmed) {
      rc = CIHX_ERR_INVALID;
      break;
    }
    if(!is_blank_or_comment(trimmed))
      rc = strvec_push(&parsed, trimmed);
    if(rc)
      break;
    if(!comma)
      break;
    cursor = comma + 1;
  }
  free(copy);
  if(!rc)
    rc = strvec_extend_move(out, &parsed);
  strvec_free(&parsed);
  return rc;
}

static int add_csv_or_file(struct strvec *out, const char *value)
{
  struct strvec parsed = {0};
  int rc;

  if(!value)
    return CIHX_ERR_INVALID;
  if(!looks_like_file(value))
    return add_csv_values(out, value);
  rc = read_lines_into(value, &parsed);
  if(!rc)
    rc = strvec_extend_move(out, &parsed);
  strvec_free(&parsed);
  return rc;
}

static void header_block_free(struct header_block *b)
{
  size_t i;

  free(b->url);
  free(b->request);
  free(b->raw);
  free(b->location);
  for(i = 0; i < b->header_count; i++) {
    free((char *)b->headers[i].name);
    free((char *)b->headers[i].value);
  }
  free(b->headers);
  memset(b, 0, sizeof(*b));
}

static void capture_free(struct capture *cap)
{
  size_t i;

  buffer_free(&cap->body);
  buffer_free(&cap->request);
  for(i = 0; i < cap->block_count; i++)
    header_block_free(&cap->blocks[i]);
  free(cap->blocks);
  memset(cap, 0, sizeof(*cap));
}

static int capture_new_block(struct capture *cap, const char *url)
{
  struct header_block *next;
  struct header_block *b;
  size_t capn;

  if(cap->block_count == cap->block_cap) {
    capn = cap->block_cap ? cap->block_cap * 2 : 4;
    next = realloc(cap->blocks, capn * sizeof(*next));
    if(!next)
      return CIHX_ERR_NOMEM;
    cap->blocks = next;
    cap->block_cap = capn;
  }
  b = &cap->blocks[cap->block_count++];
  memset(b, 0, sizeof(*b));
  b->url = xstrdup(url);
  return b->url ? CIHX_OK : CIHX_ERR_NOMEM;
}

static int header_block_add_header(struct header_block *b,
                                   const char *name,
                                   size_t name_len,
                                   const char *value,
                                   size_t value_len)
{
  struct cihx_header *next;
  size_t cap;
  char *ncopy;
  char *vcopy;

  if(b->header_count == b->header_cap) {
    cap = b->header_cap ? b->header_cap * 2 : 12;
    next = realloc(b->headers, cap * sizeof(*next));
    if(!next)
      return CIHX_ERR_NOMEM;
    b->headers = next;
    b->header_cap = cap;
  }
  ncopy = xstrndup(name, name_len);
  vcopy = xstrndup(value, value_len);
  if(!ncopy || !vcopy) {
    free(ncopy);
    free(vcopy);
    return CIHX_ERR_NOMEM;
  }
  b->headers[b->header_count].name = ncopy;
  b->headers[b->header_count].value = vcopy;
  b->header_count++;
  return CIHX_OK;
}

static char *header_block_get(const struct header_block *b, const char *name)
{
  size_t i;

  if(!b || !name)
    return NULL;
  for(i = b->header_count; i > 0; i--) {
    if(!strcasecmp(b->headers[i - 1].name, name))
      return (char *)b->headers[i - 1].value;
  }
  return NULL;
}

static long header_content_length(const struct header_block *b)
{
  const char *value = header_block_get(b, "Content-Length");
  char *end = NULL;
  long out;

  if(!value || !*value)
    return -1;
  while(isspace((unsigned char)*value))
    value++;
  errno = 0;
  out = strtol(value, &end, 10);
  if(errno || end == value || out < 0)
    return -1;
  while(end && isspace((unsigned char)*end))
    end++;
  if(end && *end)
    return -1;
  return out;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct capture *cap = userdata;
  size_t len = size * nmemb;
  if(buffer_appendn(&cap->body, ptr, len))
    return 0;
  return len;
}

static size_t debug_cb(CURL *curl, curl_infotype type, char *data,
                       size_t size, void *userdata)
{
  struct capture *cap = userdata;
  (void)curl;
  if(type == CURLINFO_HEADER_OUT || type == CURLINFO_DATA_OUT) {
    if(cap->block_count) {
      struct header_block *b = &cap->blocks[cap->block_count - 1];
      char *next = realloc(b->request, b->request_len + size + 1);
      if(next) {
        b->request = next;
        memcpy(b->request + b->request_len, data, size);
        b->request_len += size;
        b->request[b->request_len] = 0;
      }
    }
    (void)buffer_appendn(&cap->request, data, size);
  }
  return 0;
}

static size_t header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct capture *cap = userdata;
  struct header_block *b;
  char *line;
  char *colon;
  char *value;
  size_t len = size * nmemb;
  size_t value_len;

  if(cap->block_count == 0)
    return 0;
  b = &cap->blocks[cap->block_count - 1];
  if(!b->raw) {
    b->raw = malloc(1);
    if(!b->raw)
      return 0;
    b->raw[0] = 0;
  }
  {
    char *next = realloc(b->raw, b->raw_len + len + 1);
    if(!next)
      return 0;
    b->raw = next;
    memcpy(b->raw + b->raw_len, ptr, len);
    b->raw_len += len;
    b->raw[b->raw_len] = 0;
  }
  if(len >= 5 && !strncmp(ptr, "HTTP/", 5)) {
    char *space = memchr(ptr, ' ', len);
    if(space)
      b->status = strtol(space + 1, NULL, 10);
    return len;
  }
  if(len <= 2)
    return len;
  line = xstrndup(ptr, len);
  if(!line)
    return 0;
  while(len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n'))
    line[--len] = 0;
  colon = strchr(line, ':');
  if(colon) {
    char *name = line;
    size_t name_len;
    *colon = 0;
    value = trim_in_place(colon + 1);
    value_len = strlen(value);
    name_len = strlen(name);
    if(header_block_add_header(b, name, name_len, value, value_len)) {
      free(line);
      return 0;
    }
    if(!strcasecmp(name, "Location")) {
      free(b->location);
      b->location = xstrdup(value);
    }
  }
  free(line);
  return len ? size * nmemb : size * nmemb;
}

static char *tolower_dup(const char *s)
{
  char *out;
  size_t i;

  out = xstrdup(s ? s : "");
  if(!out)
    return NULL;
  for(i = 0; out[i]; i++)
    out[i] = (char)tolower((unsigned char)out[i]);
  return out;
}

static bool contains_ci(const char *haystack, const char *needle)
{
  char *h;
  char *n;
  bool found;

  if(!needle || !*needle)
    return true;
  if(!haystack)
    return false;
  h = tolower_dup(haystack);
  n = tolower_dup(needle);
  if(!h || !n) {
    free(h);
    free(n);
    return false;
  }
  found = strstr(h, n) != NULL;
  free(h);
  free(n);
  return found;
}

static long count_lines(const char *s)
{
  long lines = 0;
  bool any = false;

  if(!s || !*s)
    return 0;
  for(; *s; s++) {
    any = true;
    if(*s == '\n')
      lines++;
  }
  if(any && s[-1] != '\n')
    lines++;
  return lines;
}

static long count_words(const char *s)
{
  long words = 0;
  bool in_word = false;

  for(; s && *s; s++) {
    if(isspace((unsigned char)*s)) {
      in_word = false;
    }
    else if(!in_word) {
      words++;
      in_word = true;
    }
  }
  return words;
}

static char *normalize_preview(const char *s, size_t max_len)
{
  struct buffer out = {0};
  bool last_space = false;
  size_t i;
  int rc = CIHX_OK;

  if(!s || !max_len)
    return xstrdup("");
  for(i = 0; s[i] && out.len < max_len; i++) {
    unsigned char ch = (unsigned char)s[i];
    if(isspace(ch)) {
      if(!last_space && out.len) {
        rc = buffer_appendn(&out, " ", 1);
        last_space = true;
      }
    }
    else {
      char c = (char)ch;
      rc = buffer_appendn(&out, &c, 1);
      last_space = false;
    }
    if(rc)
      break;
  }
  while(out.len && isspace((unsigned char)out.data[out.len - 1]))
    out.data[--out.len] = 0;
  if(!out.data)
    return xstrdup("");
  return out.data;
}

static char *extract_title(const char *body)
{
  regex_t rx;
  regmatch_t m[2];
  char *title;
  char *out;
  size_t i;
  size_t j;
  bool last_space = false;

  if(!body)
    return xstrdup("");
  if(regcomp(&rx, "<[[:space:]]*title[^>]*>([^<]*)</[[:space:]]*title[[:space:]]*>",
             REG_EXTENDED | REG_ICASE | REG_NEWLINE))
    return xstrdup("");
  if(regexec(&rx, body, 2, m, 0)) {
    regfree(&rx);
    return xstrdup("");
  }
  title = xstrndup(body + m[1].rm_so, (size_t)(m[1].rm_eo - m[1].rm_so));
  regfree(&rx);
  if(!title)
    return NULL;
  out = malloc(strlen(title) + 1);
  if(!out) {
    free(title);
    return NULL;
  }
  for(i = 0, j = 0; title[i]; i++) {
    if(isspace((unsigned char)title[i])) {
      if(!last_space && j)
        out[j++] = ' ';
      last_space = true;
    }
    else {
      out[j++] = title[i];
      last_space = false;
    }
  }
  while(j && out[j - 1] == ' ')
    j--;
  out[j] = 0;
  free(title);
  return out;
}

static char *join_raw(const struct header_block *b, const char *body)
{
  struct buffer out = {0};
  if(b && b->raw)
    (void)buffer_appendn(&out, b->raw, strlen(b->raw));
  if(body)
    (void)buffer_appendn(&out, body, strlen(body));
  if(!out.data)
    return xstrdup("");
  return out.data;
}

static int result_add_extract(struct result_owned *r,
                              const char *name,
                              const char *value,
                              size_t value_len)
{
  struct cihx_extract_item *next;
  char *ncopy;
  char *vcopy;
  size_t i;

  for(i = 0; i < r->pub.extract_count; i++) {
    if(!strcmp(r->extracts[i].name, name) &&
       strlen(r->extracts[i].value) == value_len &&
       !strncmp(r->extracts[i].value, value, value_len)) {
      return CIHX_OK;
    }
  }
  next = realloc(r->extracts,
                 (r->pub.extract_count + 1) * sizeof(*r->extracts));
  if(!next)
    return CIHX_ERR_NOMEM;
  r->extracts = next;
  ncopy = xstrdup(name);
  vcopy = xstrndup(value, value_len);
  if(!ncopy || !vcopy) {
    free(ncopy);
    free(vcopy);
    return CIHX_ERR_NOMEM;
  }
  r->extracts[r->pub.extract_count].name = ncopy;
  r->extracts[r->pub.extract_count].value = vcopy;
  r->pub.extract_count++;
  r->pub.extracts = r->extracts;
  return CIHX_OK;
}

static void collect_regex_extracts(struct result_owned *r,
                                   const struct regexvec *regexes,
                                   const char *body)
{
  size_t i;

  if(!body)
    return;
  for(i = 0; i < regexes->len; i++) {
    const char *cursor = body;
    regmatch_t m[1];
    while(!regexec(&regexes->items[i], cursor, 1, m, 0)) {
      if(m[0].rm_so == m[0].rm_eo)
        break;
      (void)result_add_extract(r, regexes->patterns[i],
                               cursor + m[0].rm_so,
                               (size_t)(m[0].rm_eo - m[0].rm_so));
      cursor += m[0].rm_eo;
    }
  }
}

static void compile_and_collect_preset(struct result_owned *r,
                                       const char *name,
                                       const char *pattern,
                                       const char *body)
{
  regex_t rx;
  const char *cursor = body;
  regmatch_t m[1];

  if(!body)
    return;
  if(regcomp(&rx, pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE))
    return;
  while(!regexec(&rx, cursor, 1, m, 0)) {
    if(m[0].rm_so == m[0].rm_eo)
      break;
    (void)result_add_extract(r, name, cursor + m[0].rm_so,
                             (size_t)(m[0].rm_eo - m[0].rm_so));
    cursor += m[0].rm_eo;
  }
  regfree(&rx);
}

static char *json_escape(const char *s)
{
  struct buffer out = {0};
  const unsigned char *p = (const unsigned char *)(s ? s : "");
  char tmp[7];

  for(; *p; p++) {
    switch(*p) {
    case '\\':
      (void)buffer_appendn(&out, "\\\\", 2);
      break;
    case '"':
      (void)buffer_appendn(&out, "\\\"", 2);
      break;
    case '\b':
      (void)buffer_appendn(&out, "\\b", 2);
      break;
    case '\f':
      (void)buffer_appendn(&out, "\\f", 2);
      break;
    case '\n':
      (void)buffer_appendn(&out, "\\n", 2);
      break;
    case '\r':
      (void)buffer_appendn(&out, "\\r", 2);
      break;
    case '\t':
      (void)buffer_appendn(&out, "\\t", 2);
      break;
    default:
      if(*p < 0x20) {
        snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
        (void)buffer_appendn(&out, tmp, strlen(tmp));
      }
      else {
        (void)buffer_appendn(&out, (const char *)p, 1);
      }
      break;
    }
  }
  if(!out.data)
    return xstrdup("");
  return out.data;
}

static void json_key_string(FILE *fp, bool *first, const char *key,
                            const char *value)
{
  char *k;
  char *v;

  if(!value || !*value)
    return;
  k = json_escape(key);
  v = json_escape(value);
  if(!k || !v) {
    free(k);
    free(v);
    return;
  }
  fprintf(fp, "%s\"%s\":\"%s\"", *first ? "" : ",", k, v);
  *first = false;
  free(k);
  free(v);
}

static void json_key_long(FILE *fp, bool *first, const char *key, long value)
{
  fprintf(fp, "%s\"%s\":%ld", *first ? "" : ",", key, value);
  *first = false;
}

static void format_duration(double seconds, char *out, size_t out_len)
{
  const char *suffix = "s";
  double value = seconds;

  if(seconds < 0)
    seconds = 0;
  if(seconds < 0.000001) {
    value = seconds * 1000000000.0;
    suffix = "ns";
  }
  else if(seconds < 0.001) {
    value = seconds * 1000000.0;
    suffix = "us";
  }
  else if(seconds < 1.0) {
    value = seconds * 1000.0;
    suffix = "ms";
  }
  snprintf(out, out_len, "%.6g%s", value, suffix);
}

static void json_key_duration(FILE *fp, bool *first, const char *key,
                              double seconds)
{
  char value[64];

  format_duration(seconds, value, sizeof(value));
  json_key_string(fp, first, key, value);
}

static void json_key_bool(FILE *fp, bool *first, const char *key, bool value)
{
  fprintf(fp, "%s\"%s\":%s", *first ? "" : ",", key,
          value ? "true" : "false");
  *first = false;
}

static void json_key_long_list(FILE *fp, bool *first, const char *key,
                               const long *values, size_t count)
{
  size_t i;

  if(!count)
    return;
  fprintf(fp, "%s\"%s\":[", *first ? "" : ",", key);
  *first = false;
  for(i = 0; i < count; i++)
    fprintf(fp, "%s%ld", i ? "," : "", values[i]);
  fputc(']', fp);
}

static void json_write_headers(FILE *fp, bool *first,
                               const struct cihx_header *headers,
                               size_t count)
{
  size_t i;
  size_t emitted = 0;

  if(!count)
    return;
  fprintf(fp, "%s\"header\":{", *first ? "" : ",");
  *first = false;
  for(i = 0; i < count; i++) {
    size_t j;
    char *k = json_escape(headers[i].name);
    char *v = json_escape(headers[i].value);
    bool shadowed = false;

    for(j = i + 1; j < count; j++) {
      if(!strcasecmp(headers[i].name, headers[j].name)) {
        shadowed = true;
        break;
      }
    }
    if(shadowed) {
      free(k);
      free(v);
      continue;
    }
    if(k && v) {
      fprintf(fp, "%s\"%s\":\"%s\"", emitted ? "," : "", k, v);
      emitted++;
    }
    free(k);
    free(v);
  }
  fputc('}', fp);
}

static void json_write_chain(FILE *fp, bool *first,
                             const struct cihx_chain_item *chain,
                             size_t count)
{
  size_t i;

  if(!count)
    return;
  fprintf(fp, "%s\"chain\":[", *first ? "" : ",");
  *first = false;
  for(i = 0; i < count; i++) {
    bool inner = true;
    fprintf(fp, "%s{", i ? "," : "");
    json_key_string(fp, &inner, "url", chain[i].url);
    json_key_long(fp, &inner, "status_code", chain[i].status_code);
    json_key_string(fp, &inner, "location", chain[i].location);
    json_key_string(fp, &inner, "request-url", chain[i].request_url);
    json_key_string(fp, &inner, "request", chain[i].request);
    json_key_string(fp, &inner, "response", chain[i].response);
    json_key_string(fp, &inner, "raw_header", chain[i].raw_header);
    fputc('}', fp);
  }
  fputc(']', fp);
}

static void json_write_extracts(FILE *fp, bool *first,
                                const struct cihx_extract_item *items,
                                size_t count)
{
  size_t i;
  size_t emitted = 0;

  if(!count)
    return;
  fprintf(fp, "%s\"extracts\":{", *first ? "" : ",");
  *first = false;
  for(i = 0; i < count; i++) {
    char *k = json_escape(items[i].name);
    size_t j;
    size_t value_count = 0;
    bool seen = false;

    for(j = 0; j < i; j++) {
      if(!strcmp(items[j].name, items[i].name)) {
        seen = true;
        break;
      }
    }
    if(seen) {
      free(k);
      continue;
    }
    if(k)
      fprintf(fp, "%s\"%s\":[", emitted ? "," : "", k);
    for(j = i; k && j < count; j++) {
      if(!strcmp(items[j].name, items[i].name)) {
        char *v = json_escape(items[j].value);
        if(v) {
          fprintf(fp, "%s\"%s\"", value_count ? "," : "", v);
          value_count++;
        }
        free(v);
      }
    }
    if(k) {
      fputc(']', fp);
      emitted++;
    }
    free(k);
  }
  fputc('}', fp);
}

static void json_key_string_list(FILE *fp, bool *first, const char *key,
                                 const char *csv)
{
  char *copy;
  char *tok;
  char *save = NULL;
  size_t emitted = 0;

  if(!csv || !*csv)
    return;
  copy = xstrdup(csv);
  if(!copy)
    return;
  fprintf(fp, "%s\"%s\":[", *first ? "" : ",", key);
  *first = false;
  for(tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
    char *trimmed = trim_in_place(tok);
    char *escaped;
    if(!*trimmed)
      continue;
    escaped = json_escape(trimmed);
    if(!escaped)
      continue;
    fprintf(fp, "%s\"%s\"", emitted ? "," : "", escaped);
    emitted++;
    free(escaped);
  }
  fputc(']', fp);
  free(copy);
}

static void result_write_json(FILE *fp, const struct cihx_result *r)
{
  bool first = true;

  fputc('{', fp);
  json_key_string(fp, &first, "url", r->url);
  json_key_string(fp, &first, "input", r->input);
  json_key_string(fp, &first, "final_url", r->final_url);
  json_key_string(fp, &first, "scheme", r->scheme);
  json_key_string(fp, &first, "host", r->host);
  json_key_string(fp, &first, "host_ip", r->host_ip);
  json_key_string(fp, &first, "port", r->port);
  json_key_string(fp, &first, "path", r->path);
  json_key_string(fp, &first, "method", r->method);
  json_key_long(fp, &first, "status_code", r->status_code);
  json_key_long(fp, &first, "content_length", r->content_length);
  json_key_long(fp, &first, "lines", r->lines);
  json_key_long(fp, &first, "words", r->words);
  json_key_duration(fp, &first, "time", r->response_time);
  json_key_bool(fp, &first, "failed", r->failed);
  json_key_string(fp, &first, "location", r->location);
  json_key_string(fp, &first, "title", r->title);
  json_key_string(fp, &first, "webserver", r->webserver);
  json_key_string(fp, &first, "content_type", r->content_type);
  json_key_string(fp, &first, "body_preview", r->body_preview);
  json_key_string(fp, &first, "body", r->response_body);
  json_key_string(fp, &first, "raw_header", r->raw_header);
  json_key_string(fp, &first, "request", r->request);
  json_key_string(fp, &first, "error", r->error);
  json_key_bool(fp, &first, "cdn", r->cdn);
  json_key_string(fp, &first, "cdn_name", r->cdn_name);
  json_key_string(fp, &first, "cdn_type", r->cdn_type);
  json_key_string_list(fp, &first, "tech", r->tech);
  json_write_headers(fp, &first, r->headers, r->header_count);
  json_key_long_list(fp, &first, "chain_status_codes",
                     r->chain_status_codes, r->chain_status_code_count);
  json_write_chain(fp, &first, r->chain, r->chain_count);
  json_write_extracts(fp, &first, r->extracts, r->extract_count);
  fputs("}\n", fp);
}

int cihx_result_write_json(FILE *fp, const cihx_result *result)
{
  if(!fp || !result)
    return CIHX_ERR_INVALID;
  result_write_json(fp, result);
  return ferror(fp) ? CIHX_ERR_IO : CIHX_OK;
}

static bool has_scheme(const char *s)
{
  const char *p = s;
  if(!s || !isalpha((unsigned char)*s))
    return false;
  while(*p && (isalnum((unsigned char)*p) || *p == '+' || *p == '-' ||
               *p == '.'))
    p++;
  return p[0] == ':' && p[1] == '/' && p[2] == '/';
}

static char *url_part(const char *url, CURLUPart part)
{
  CURLU *u;
  char *tmp = NULL;
  char *out = NULL;

  u = curl_url();
  if(!u)
    return NULL;
  if(!curl_url_set(u, CURLUPART_URL, url, 0) &&
     !curl_url_get(u, part, &tmp, 0)) {
    out = xstrdup(tmp);
    curl_free(tmp);
  }
  curl_url_cleanup(u);
  return out;
}

static char *url_scheme(const char *url)
{
  return url_part(url, CURLUPART_SCHEME);
}

static char *url_host(const char *url)
{
  return url_part(url, CURLUPART_HOST);
}

static long url_effective_port(const char *url)
{
  CURLU *u;
  char *scheme = NULL;
  char *port = NULL;
  long out = 0;

  u = curl_url();
  if(!u)
    return 0;
  if(curl_url_set(u, CURLUPART_URL, url, 0))
    goto done;
  if(!curl_url_get(u, CURLUPART_PORT, &port, 0) && port) {
    out = strtol(port, NULL, 10);
    goto done;
  }
  if(!curl_url_get(u, CURLUPART_SCHEME, &scheme, 0)) {
    if(!strcmp(scheme, "http"))
      out = 80;
    else if(!strcmp(scheme, "https"))
      out = 443;
  }
done:
  curl_free(scheme);
  curl_free(port);
  curl_url_cleanup(u);
  return out;
}

static char *url_effective_port_string(const char *url)
{
  char buf[32];
  long port = url_effective_port(url);

  if(port <= 0)
    return xstrdup("");
  snprintf(buf, sizeof(buf), "%ld", port);
  return xstrdup(buf);
}

static char *url_authority(const char *url)
{
  CURLU *u;
  char *host = NULL;
  char *port = NULL;
  char *out = NULL;
  struct buffer b = {0};

  u = curl_url();
  if(!u)
    return NULL;
  if(curl_url_set(u, CURLUPART_URL, url, 0))
    goto out;
  if(curl_url_get(u, CURLUPART_HOST, &host, 0))
    goto out;
  (void)buffer_appendn(&b, host, strlen(host));
  if(!curl_url_get(u, CURLUPART_PORT, &port, 0) && port && *port) {
    (void)buffer_appendn(&b, ":", 1);
    (void)buffer_appendn(&b, port, strlen(port));
  }
  out = b.data;
  b.data = NULL;
out:
  curl_free(host);
  curl_free(port);
  curl_url_cleanup(u);
  buffer_free(&b);
  return out;
}

static char *url_path(const char *url)
{
  char *path = url_part(url, CURLUPART_PATH);
  if(!path || !*path) {
    free(path);
    return xstrdup("/");
  }
  return path;
}

static char *make_base_url(const char *scheme, const char *target)
{
  struct buffer out = {0};
  if(has_scheme(target)) {
    CURLU *u;
    char *tmp = NULL;
    char *copy = NULL;

    u = curl_url();
    if(!u)
      return NULL;
    if(!curl_url_set(u, CURLUPART_URL, target, 0) &&
       !curl_url_set(u, CURLUPART_SCHEME, scheme, 0) &&
       !curl_url_get(u, CURLUPART_URL, &tmp, 0)) {
      copy = xstrdup(tmp);
      curl_free(tmp);
    }
    curl_url_cleanup(u);
    return copy;
  }
  (void)buffer_appendf(&out, "%s://%s", scheme, target);
  return out.data ? out.data : xstrdup("");
}

static char *apply_path(const char *base, const char *path)
{
  CURLU *u;
  char *normalized = NULL;
  char *query = NULL;
  char *query_copy = NULL;
  char *out_tmp = NULL;
  char *out = NULL;
  struct buffer with_query = {0};

  if(!path)
    return xstrdup(base);
  u = curl_url();
  if(!u)
    return NULL;
  if(curl_url_set(u, CURLUPART_URL, base, 0))
    goto done;
  normalized = xstrdup(*path ? path : "/");
  if(!normalized)
    goto done;
  query = strchr(normalized, '?');
  if(query) {
    *query++ = 0;
    if(*query) {
      query_copy = xstrdup(query);
      if(!query_copy)
        goto done;
    }
  }
  if(!*normalized) {
    free(normalized);
    normalized = xstrdup("/");
    if(!normalized)
      goto done;
  }
  if(normalized[0] != '/') {
    char *with_slash;
    size_t len = strlen(normalized);
    with_slash = malloc(len + 2);
    if(!with_slash)
      goto done;
    with_slash[0] = '/';
    memcpy(with_slash + 1, normalized, len + 1);
    free(normalized);
    normalized = with_slash;
  }
  if(curl_url_set(u, CURLUPART_PATH, normalized, 0))
    goto done;
  if(curl_url_set(u, CURLUPART_QUERY, NULL, 0))
    goto done;
  if(!curl_url_get(u, CURLUPART_URL, &out_tmp, 0)) {
    if(query_copy && *query_copy) {
      (void)buffer_appendn(&with_query, out_tmp, strlen(out_tmp));
      (void)buffer_appendn(&with_query, "?", 1);
      (void)buffer_appendn(&with_query, query_copy, strlen(query_copy));
      out = with_query.data;
      with_query.data = NULL;
    }
    else {
      out = xstrdup(out_tmp);
    }
    curl_free(out_tmp);
  }
done:
  buffer_free(&with_query);
  free(query_copy);
  free(normalized);
  curl_url_cleanup(u);
  return out;
}

static char *apply_port(const char *url, long port)
{
  CURLU *u;
  char portbuf[32];
  char *tmp = NULL;
  char *out = NULL;

  if(port <= 0)
    return xstrdup(url);
  u = curl_url();
  if(!u)
    return NULL;
  snprintf(portbuf, sizeof(portbuf), "%ld", port);
  if(!curl_url_set(u, CURLUPART_URL, url, 0) &&
     !curl_url_set(u, CURLUPART_PORT, portbuf, 0) &&
     !curl_url_get(u, CURLUPART_URL, &tmp, 0)) {
    out = xstrdup(tmp);
    curl_free(tmp);
  }
  curl_url_cleanup(u);
  return out;
}

static char *resolve_location(const char *base, const char *location)
{
  char *scheme = NULL;
  char *authority = NULL;
  char *path = NULL;
  struct buffer out = {0};

  if(!location || !*location)
    return NULL;
  if(has_scheme(location))
    return xstrdup(location);
  scheme = url_scheme(base);
  authority = url_authority(base);
  if(!scheme || !authority)
    goto out;
  if(location[0] == '/' && location[1] == '/') {
    (void)buffer_appendf(&out, "%s:%s", scheme, location);
  }
  else if(location[0] == '/') {
    (void)buffer_appendf(&out, "%s://%s%s", scheme, authority, location);
  }
  else if(location[0] == '?') {
    path = url_path(base);
    (void)buffer_appendf(&out, "%s://%s%s%s", scheme, authority,
                         path ? path : "/", location);
  }
  else {
    char *slash;
    path = url_path(base);
    slash = strrchr(path, '/');
    if(slash)
      slash[1] = 0;
    (void)buffer_appendf(&out, "%s://%s%s%s", scheme, authority,
                         path ? path : "/", location);
  }
out:
  free(scheme);
  free(authority);
  free(path);
  return out.data;
}

static int add_port_spec(struct cihx_options *opts,
                         const char *scheme,
                         long port)
{
  struct port_spec *next;
  size_t cap;
  size_t i;

  if(port <= 0 || port > 65535)
    return CIHX_ERR_INVALID;
  for(i = 0; i < opts->port_count; i++) {
    const char *existing_scheme = opts->ports[i].scheme ?
                                  opts->ports[i].scheme : "";
    const char *new_scheme = scheme ? scheme : "";
    if(opts->ports[i].port == port && !strcmp(existing_scheme, new_scheme))
      return CIHX_OK;
  }
  if(opts->port_count == opts->port_cap) {
    cap = opts->port_cap ? opts->port_cap * 2 : 8;
    next = realloc(opts->ports, cap * sizeof(*next));
    if(!next)
      return CIHX_ERR_NOMEM;
    opts->ports = next;
    opts->port_cap = cap;
  }
  opts->ports[opts->port_count].scheme = xstrdup(scheme ? scheme : "");
  if(!opts->ports[opts->port_count].scheme)
    return CIHX_ERR_NOMEM;
  opts->ports[opts->port_count].port = port;
  opts->port_count++;
  return CIHX_OK;
}

static int parse_port_item(struct cihx_options *opts,
                           const char *scheme,
                           const char *item)
{
  char *copy;
  char *dash;
  char *end = NULL;
  long start;
  long stop;
  long p;
  int rc = CIHX_OK;

  copy = xstrdup(item);
  if(!copy)
    return CIHX_ERR_NOMEM;
  item = trim_in_place(copy);
  dash = strchr(item, '-');
  errno = 0;
  start = strtol(item, &end, 10);
  if(errno || end == item) {
    free(copy);
    return CIHX_ERR_INVALID;
  }
  if(dash) {
    char *end2 = NULL;
    errno = 0;
    stop = strtol(dash + 1, &end2, 10);
    if(errno || end2 == dash + 1 || *trim_in_place(end2) || stop < start) {
      free(copy);
      return CIHX_ERR_INVALID;
    }
  }
  else {
    if(*trim_in_place(end)) {
      free(copy);
      return CIHX_ERR_INVALID;
    }
    stop = start;
  }
  for(p = start; p <= stop; p++) {
    rc = add_port_spec(opts, scheme, p);
    if(rc)
      break;
  }
  free(copy);
  return rc;
}

static int parse_ports(struct cihx_options *opts, const char *expr)
{
  char *copy;
  char *tok;
  char *save = NULL;
  char current_scheme[16] = "";
  int rc = CIHX_OK;

  if(!expr || !*expr)
    return CIHX_OK;
  if(csv_has_empty_item(expr))
    return CIHX_ERR_INVALID;
  copy = xstrdup(expr);
  if(!copy)
    return CIHX_ERR_NOMEM;
  for(tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
    char *s = trim_in_place(tok);
    char *colon = strchr(s, ':');
    if(!*s)
      continue;
    if(colon && colon != s) {
      size_t n = (size_t)(colon - s);
      size_t i;
      if(n >= sizeof(current_scheme)) {
        rc = CIHX_ERR_INVALID;
        break;
      }
      memcpy(current_scheme, s, n);
      current_scheme[n] = 0;
      for(i = 0; current_scheme[i]; i++)
        current_scheme[i] = (char)tolower((unsigned char)current_scheme[i]);
      if(strcmp(current_scheme, "http") && strcmp(current_scheme, "https") &&
         strcmp(current_scheme, "http&https")) {
        rc = CIHX_ERR_INVALID;
        break;
      }
      s = colon + 1;
    }
    if(!strcmp(current_scheme, "http&https")) {
      rc = parse_port_item(opts, "https", s);
      if(!rc)
        rc = parse_port_item(opts, "http", s);
    }
    else {
      rc = parse_port_item(opts, current_scheme[0] ? current_scheme : NULL, s);
    }
    if(rc)
      break;
  }
  free(copy);
  return rc;
}

static int resolve_host_ips(const char *host, struct strvec *ips)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *ai;
  int gai;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  gai = getaddrinfo(host, NULL, &hints, &res);
  if(gai)
    return CIHX_ERR_INVALID;
  for(ai = res; ai; ai = ai->ai_next) {
    char buf[INET6_ADDRSTRLEN];
    void *addr = NULL;

    if(ai->ai_family == AF_INET) {
      addr = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
    }
    else if(ai->ai_family == AF_INET6) {
      addr = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
    }
    if(addr && inet_ntop(ai->ai_family, addr, buf, sizeof(buf)) &&
       !strvec_contains(ips, buf)) {
      int rc = strvec_push(ips, buf);
      if(rc) {
        freeaddrinfo(res);
        return rc;
      }
    }
  }
  freeaddrinfo(res);
  return ips->len ? CIHX_OK : CIHX_ERR_INVALID;
}

static char *make_resolve_entry(const char *url, const char *ip)
{
  char *host = NULL;
  long port;
  struct buffer out = {0};

  if(!ip || !*ip)
    return NULL;
  host = url_host(url);
  port = url_effective_port(url);
  if(!host || port <= 0)
    goto done;
  if(strchr(ip, ':'))
    (void)buffer_appendf(&out, "%s:%ld:[%s]", host, port, ip);
  else
    (void)buffer_appendf(&out, "%s:%ld:%s", host, port, ip);
done:
  free(host);
  return out.data;
}

static bool parse_cidr(const char *cidr,
                       unsigned char *network,
                       int *family,
                       int *prefix_bits)
{
  char buf[INET6_ADDRSTRLEN + 8];
  char *slash;
  char *end = NULL;
  long prefix;

  if(strlen(cidr) >= sizeof(buf))
    return false;
  strcpy(buf, cidr);
  slash = strchr(buf, '/');
  if(!slash)
    return false;
  *slash++ = 0;
  errno = 0;
  prefix = strtol(slash, &end, 10);
  if(errno || end == slash || *end)
    return false;
  *family = strchr(buf, ':') ? AF_INET6 : AF_INET;
  if((*family == AF_INET && (prefix < 0 || prefix > 32)) ||
     (*family == AF_INET6 && (prefix < 0 || prefix > 128)))
    return false;
  if(inet_pton(*family, buf, network) != 1)
    return false;
  *prefix_bits = (int)prefix;
  return true;
}

static bool ip_in_cidr(const char *ip, const char *cidr)
{
  unsigned char ip_bytes[16];
  unsigned char network[16];
  int family;
  int cidr_family;
  int prefix_bits;
  int full_bytes;
  int rem_bits;

  if(!ip || !*ip || !cidr || !*cidr)
    return false;
  family = strchr(ip, ':') ? AF_INET6 : AF_INET;
  memset(ip_bytes, 0, sizeof(ip_bytes));
  memset(network, 0, sizeof(network));
  if(inet_pton(family, ip, ip_bytes) != 1)
    return false;
  if(!parse_cidr(cidr, network, &cidr_family, &prefix_bits) ||
     family != cidr_family)
    return false;
  full_bytes = prefix_bits / 8;
  rem_bits = prefix_bits % 8;
  if(full_bytes && memcmp(ip_bytes, network, (size_t)full_bytes))
    return false;
  if(rem_bits) {
    unsigned char mask = (unsigned char)(0xffu << (8 - rem_bits));
    if((ip_bytes[full_bytes] & mask) != (network[full_bytes] & mask))
      return false;
  }
  return true;
}

static int setup_easy(CURL *easy, const struct cihx_options *opts,
                      const char *url, const char *method,
                      const char *referer, const char *resolve_ip,
                      struct capture *cap, struct curl_slist **headers_out,
                      struct curl_slist **resolve_out)
{
  struct curl_slist *headers = NULL;
  struct curl_slist *resolve = NULL;
  size_t i;
  CURLcode cc;

  cc = curl_easy_setopt(easy, CURLOPT_URL, url);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_WRITEDATA, cap);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, header_cb);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_HEADERDATA, cap);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, debug_cb);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_DEBUGDATA, cap);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, cap->error);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_TIMEOUT, opts->timeout_seconds);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
  if(cc)
    return CIHX_ERR_CURL;
  cc = curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING, "");
  if(cc)
    return CIHX_ERR_CURL;
  if(opts->proxy) {
    cc = curl_easy_setopt(easy, CURLOPT_PROXY, opts->proxy);
    if(cc)
      return CIHX_ERR_CURL;
  }
  if(opts->random_agent && !headers_include_name(&opts->headers, "User-Agent")) {
    size_t count = sizeof(random_user_agents) / sizeof(random_user_agents[0]);
    const char *agent = random_user_agents[(size_t)rand() % count];
    cc = curl_easy_setopt(easy, CURLOPT_USERAGENT, agent);
    if(cc)
      return CIHX_ERR_CURL;
  }
  if(opts->resolvers.len) {
    char *dns_servers = strvec_join(&opts->resolvers, ",");
    if(!dns_servers)
      return CIHX_ERR_NOMEM;
    cc = curl_easy_setopt(easy, CURLOPT_DNS_SERVERS, dns_servers);
    free(dns_servers);
    if(cc)
      return CIHX_ERR_CURL;
  }
  if(resolve_ip) {
    char *entry = make_resolve_entry(url, resolve_ip);
    struct curl_slist *next;
    if(!entry)
      return CIHX_ERR_NOMEM;
    next = curl_slist_append(resolve, entry);
    free(entry);
    if(!next)
      return CIHX_ERR_NOMEM;
    resolve = next;
    cc = curl_easy_setopt(easy, CURLOPT_RESOLVE, resolve);
    if(cc) {
      curl_slist_free_all(resolve);
      return CIHX_ERR_CURL;
    }
  }
  if(referer) {
    cc = curl_easy_setopt(easy, CURLOPT_REFERER, referer);
    if(cc)
      return CIHX_ERR_CURL;
  }
  if(method && strcmp(method, "GET")) {
    if(!strcmp(method, "HEAD")) {
      cc = curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
    }
    else if(!strcmp(method, "POST")) {
      cc = curl_easy_setopt(easy, CURLOPT_POST, 1L);
      if(!cc && opts->body)
        cc = curl_easy_setopt(easy, CURLOPT_POSTFIELDS, opts->body);
    }
    else {
      cc = curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
      if(!cc && opts->body)
        cc = curl_easy_setopt(easy, CURLOPT_POSTFIELDS, opts->body);
    }
    if(cc)
      return CIHX_ERR_CURL;
  }
  for(i = 0; i < opts->headers.len; i++) {
    struct curl_slist *next = curl_slist_append(headers, opts->headers.items[i]);
    if(!next) {
      curl_slist_free_all(headers);
      return CIHX_ERR_NOMEM;
    }
    headers = next;
  }
  if(headers) {
    cc = curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
    if(cc) {
      curl_slist_free_all(headers);
      return CIHX_ERR_CURL;
    }
  }
  *headers_out = headers;
  *resolve_out = resolve;
  return CIHX_OK;
}

static char *detect_tech(const struct header_block *headers, const char *body)
{
  struct buffer out = {0};
  struct strvec matches = {0};
  size_t i;

  for(i = 0; i < sizeof(tech_signatures) / sizeof(tech_signatures[0]); i++) {
    const struct tech_signature *sig = &tech_signatures[i];
    bool matched = false;

    if(sig->header_name && sig->header_contains) {
      const char *value = header_block_get(headers, sig->header_name);
      matched = value && contains_ci(value, sig->header_contains);
    }
    if(!matched && sig->body_contains) {
      matched = body && contains_ci(body, sig->body_contains);
    }
    if(matched && !strvec_contains(&matches, sig->name))
      (void)strvec_push(&matches, sig->name);
  }
  for(i = 0; i < matches.len; i++) {
    if(i)
      (void)buffer_appendn(&out, ",", 1);
    (void)buffer_appendn(&out, matches.items[i], strlen(matches.items[i]));
  }
  strvec_free(&matches);
  return out.data ? out.data : xstrdup("");
}

static void detect_cdn(struct result_owned *r, const struct header_block *headers)
{
  size_t i;

  r->pub.cdn = false;
  for(i = 0; i < sizeof(cdn_cidr_signatures) / sizeof(cdn_cidr_signatures[0]); i++) {
    if(ip_in_cidr(r->pub.host_ip, cdn_cidr_signatures[i].cidr)) {
      r->cdn_name = xstrdup(cdn_cidr_signatures[i].name);
      r->cdn_type = xstrdup(cdn_cidr_signatures[i].type);
      break;
    }
  }
  for(i = 0; !r->cdn_name &&
             i < sizeof(cdn_header_signatures) / sizeof(cdn_header_signatures[0]); i++) {
    const struct cdn_header_signature *sig = &cdn_header_signatures[i];
    const char *value = headers ? header_block_get(headers, sig->header_name) : NULL;
    if(!value && sig->header_name && !strcasecmp(sig->header_name, "Server"))
      value = r->pub.webserver;
    if(value && (!sig->header_contains[0] ||
                 contains_ci(value, sig->header_contains))) {
      r->cdn_name = xstrdup(sig->name);
      r->cdn_type = xstrdup(sig->type);
      break;
    }
  }
  if(r->cdn_name) {
    r->pub.cdn = true;
    r->pub.cdn_name = r->cdn_name;
    r->pub.cdn_type = r->cdn_type;
  }
}

static void result_free(struct result_owned *r)
{
  size_t i;

  free(r->url);
  free(r->input);
  free(r->final_url);
  free(r->scheme);
  free(r->host);
  free(r->host_ip);
  free(r->port);
  free(r->path);
  free(r->method);
  free(r->location);
  free(r->title);
  free(r->webserver);
  free(r->content_type);
  free(r->body_preview);
  free(r->response_body);
  free(r->raw_header);
  free(r->request);
  free(r->error);
  free(r->cdn_name);
  free(r->cdn_type);
  free(r->tech);
  if(r->headers) {
    for(i = 0; i < r->pub.header_count; i++) {
      free((char *)r->headers[i].name);
      free((char *)r->headers[i].value);
    }
    free(r->headers);
  }
  if(r->chain) {
    for(i = 0; i < r->pub.chain_count; i++) {
      free((char *)r->chain[i].url);
      free((char *)r->chain[i].location);
      free((char *)r->chain[i].request_url);
      free((char *)r->chain[i].request);
      free((char *)r->chain[i].response);
      free((char *)r->chain[i].raw_header);
    }
    free(r->chain);
  }
  free(r->chain_status_codes);
  if(r->extracts) {
    for(i = 0; i < r->pub.extract_count; i++) {
      free((char *)r->extracts[i].name);
      free((char *)r->extracts[i].value);
    }
    free(r->extracts);
  }
  memset(r, 0, sizeof(*r));
}

static int clone_headers(struct result_owned *r, const struct header_block *b)
{
  size_t i;

  if(!b || !b->header_count)
    return CIHX_OK;
  r->headers = xcalloc(b->header_count, sizeof(*r->headers));
  if(!r->headers)
    return CIHX_ERR_NOMEM;
  for(i = 0; i < b->header_count; i++) {
    r->headers[i].name = xstrdup(b->headers[i].name);
    r->headers[i].value = xstrdup(b->headers[i].value);
    if(!r->headers[i].name || !r->headers[i].value)
      return CIHX_ERR_NOMEM;
  }
  r->pub.headers = r->headers;
  r->pub.header_count = b->header_count;
  return CIHX_OK;
}

static int clone_chain(struct result_owned *r, const struct capture *cap)
{
  size_t i;

  if(!cap->block_count)
    return CIHX_OK;
  r->chain = xcalloc(cap->block_count, sizeof(*r->chain));
  r->chain_status_codes = xcalloc(cap->block_count,
                                  sizeof(*r->chain_status_codes));
  if(!r->chain || !r->chain_status_codes)
    return CIHX_ERR_NOMEM;
  for(i = 0; i < cap->block_count; i++) {
    r->chain[i].url = xstrdup(cap->blocks[i].url);
    r->chain[i].status_code = cap->blocks[i].status;
    r->chain[i].location = xstrdup(cap->blocks[i].location);
    r->chain[i].request_url = xstrdup(cap->blocks[i].url);
    r->chain[i].request = xstrdup(cap->blocks[i].request);
    r->chain[i].response = xstrdup(cap->blocks[i].raw);
    r->chain[i].raw_header = xstrdup(cap->blocks[i].raw);
    r->chain_status_codes[i] = cap->blocks[i].status;
    if(!r->chain[i].url || !r->chain[i].request_url)
      return CIHX_ERR_NOMEM;
  }
  r->pub.chain = r->chain;
  r->pub.chain_count = cap->block_count;
  r->pub.chain_status_codes = r->chain_status_codes;
  r->pub.chain_status_code_count = cap->block_count;
  return CIHX_OK;
}

static int build_result(const struct cihx_options *opts,
                        const char *input,
                        const char *method,
                        const char *final_url,
                        const char *host_ip,
                        struct capture *cap,
                        CURLcode curl_code,
                        double response_time,
                        struct result_owned *r)
{
  struct header_block *b = NULL;
  char *raw = NULL;
  long code = 0;
  long cl = -1;
  memset(r, 0, sizeof(*r));
  if(cap->block_count)
    b = &cap->blocks[cap->block_count - 1];
  raw = join_raw(b, cap->body.data);
  r->url = xstrdup(final_url);
  r->input = xstrdup(input);
  r->final_url = cap->block_count > 1 ? xstrdup(final_url) : NULL;
  r->scheme = url_scheme(final_url);
  r->host = url_host(final_url);
  r->host_ip = xstrdup(host_ip ? host_ip : cap->primary_ip);
  r->port = url_effective_port_string(final_url);
  r->path = url_path(final_url);
  r->method = xstrdup(method);
  r->location = xstrdup(b ? b->location : NULL);
  r->webserver = xstrdup(b ? header_block_get(b, "Server") : NULL);
  r->content_type = xstrdup(b ? header_block_get(b, "Content-Type") : NULL);
  r->raw_header = xstrdup(b ? b->raw : NULL);
  r->request = xstrdup(cap->request.data);
  r->title = extract_title(cap->body.data);
  r->body_preview = normalize_preview(cap->body.data, opts->body_preview_size);
  r->response_body = xstrdup(cap->body.data);
  if(curl_code) {
    const char *msg = cap->error[0] ? cap->error : curl_easy_strerror(curl_code);
    r->error = xstrdup(msg);
  }
  if((opts->probe_flags & CIHX_PROBE_TECH_DETECT) != 0)
    r->tech = detect_tech(b, cap->body.data);

  if(!r->url || !r->input || !r->scheme || !r->host || !r->port || !r->path ||
     !r->method || !r->title || !r->body_preview || !raw)
    goto nomem;

  code = b ? b->status : 0;
  cl = header_content_length(b);
  if(cl < 0)
    cl = (long)cap->body.len;
  r->pub.url = r->url;
  r->pub.input = r->input;
  r->pub.final_url = r->final_url;
  r->pub.scheme = r->scheme;
  r->pub.host = r->host;
  r->pub.host_ip = r->host_ip;
  r->pub.port = r->port;
  r->pub.path = r->path;
  r->pub.method = r->method;
  r->pub.location = r->location;
  r->pub.title = r->title;
  r->pub.webserver = r->webserver;
  r->pub.content_type = r->content_type;
  r->pub.body_preview = r->body_preview;
  r->pub.response_body = opts->include_response ? r->response_body : NULL;
  r->pub.raw_header = (opts->include_response_header || opts->include_response) ?
                      r->raw_header : NULL;
  r->pub.request = opts->include_response ? r->request : NULL;
  r->pub.error = r->error;
  r->pub.tech = r->tech;
  r->pub.status_code = code;
  r->pub.content_length = cl;
  r->pub.lines = count_lines(cap->body.data);
  r->pub.words = count_words(cap->body.data);
  r->pub.response_time = response_time;
  r->pub.failed = curl_code != CURLE_OK;

  if((opts->include_response_header || opts->include_response) &&
     clone_headers(r, b))
    goto nomem;
  if(opts->include_chain && clone_chain(r, cap))
    goto nomem;
  if(opts->extract_regexes.len)
    collect_regex_extracts(r, &opts->extract_regexes, raw);
  if(opts->extract_presets & CIHX_EXTRACT_PRESET_URL)
    compile_and_collect_preset(r, "url",
      "https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+", raw);
  if(opts->extract_presets & CIHX_EXTRACT_PRESET_IPV4)
    compile_and_collect_preset(r, "ipv4",
      "([0-9]{1,3}\\.){3}[0-9]{1,3}", raw);
  if(opts->extract_presets & CIHX_EXTRACT_PRESET_MAIL)
    compile_and_collect_preset(r, "mail",
      "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", raw);
  if((opts->probe_flags & CIHX_PROBE_CDN) || opts->match_cdn.len ||
     opts->filter_cdn.len)
    detect_cdn(r, b);
  free(raw);
  return CIHX_OK;

nomem:
  free(raw);
  result_free(r);
  return CIHX_ERR_NOMEM;
}

static bool result_matches_regex_all(const struct regexvec *regexes,
                                     const char *raw)
{
  size_t i;
  for(i = 0; i < regexes->len; i++) {
    if(regexec(&regexes->items[i], raw ? raw : "", 0, NULL, 0))
      return false;
  }
  return true;
}

static bool result_matches_regex_any(const struct regexvec *regexes,
                                     const char *raw)
{
  size_t i;
  for(i = 0; i < regexes->len; i++) {
    if(!regexec(&regexes->items[i], raw ? raw : "", 0, NULL, 0))
      return true;
  }
  return false;
}

enum condition_value_type {
  COND_VALUE_MISSING,
  COND_VALUE_NUMBER,
  COND_VALUE_STRING,
  COND_VALUE_BOOL
};

struct condition_value {
  enum condition_value_type type;
  double number;
  const char *string;
  bool boolean;
};

struct condition_parser {
  const char *s;
  const struct cihx_result *result;
  bool validate_only;
  bool ok;
};

static void condition_skip_ws(struct condition_parser *p)
{
  while(*p->s && isspace((unsigned char)*p->s))
    p->s++;
}

static bool condition_match_word(struct condition_parser *p, const char *word)
{
  size_t len = strlen(word);
  condition_skip_ws(p);
  if(strncmp(p->s, word, len))
    return false;
  if(isalnum((unsigned char)p->s[len]) || p->s[len] == '_')
    return false;
  p->s += len;
  return true;
}

static bool condition_parse_identifier(struct condition_parser *p,
                                       char *out,
                                       size_t out_len)
{
  size_t len = 0;

  condition_skip_ws(p);
  if(!(isalpha((unsigned char)*p->s) || *p->s == '_'))
    return false;
  while(isalnum((unsigned char)*p->s) || *p->s == '_') {
    if(len + 1 >= out_len)
      return false;
    out[len++] = *p->s++;
  }
  out[len] = 0;
  return true;
}

static struct condition_value condition_field_value(const struct cihx_result *r,
                                                    const char *field)
{
  struct condition_value v;
  memset(&v, 0, sizeof(v));
  v.type = COND_VALUE_MISSING;

#define STRING_FIELD(name, member) \
  if(!strcmp(field, name)) { v.type = COND_VALUE_STRING; v.string = r->member; return v; }
#define NUMBER_FIELD(name, member) \
  if(!strcmp(field, name)) { v.type = COND_VALUE_NUMBER; v.number = (double)r->member; return v; }
#define BOOL_FIELD(name, member) \
  if(!strcmp(field, name)) { v.type = COND_VALUE_BOOL; v.boolean = r->member; return v; }

  STRING_FIELD("url", url)
  STRING_FIELD("input", input)
  STRING_FIELD("final_url", final_url)
  STRING_FIELD("scheme", scheme)
  STRING_FIELD("host", host)
  STRING_FIELD("host_ip", host_ip)
  STRING_FIELD("port", port)
  STRING_FIELD("path", path)
  STRING_FIELD("method", method)
  STRING_FIELD("location", location)
  STRING_FIELD("title", title)
  STRING_FIELD("webserver", webserver)
  STRING_FIELD("content_type", content_type)
  STRING_FIELD("body_preview", body_preview)
  STRING_FIELD("body", response_body)
  STRING_FIELD("raw_header", raw_header)
  STRING_FIELD("request", request)
  STRING_FIELD("error", error)
  STRING_FIELD("cdn_name", cdn_name)
  STRING_FIELD("cdn_type", cdn_type)
  STRING_FIELD("tech", tech)
  NUMBER_FIELD("status_code", status_code)
  NUMBER_FIELD("content_length", content_length)
  NUMBER_FIELD("words", words)
  NUMBER_FIELD("lines", lines)
  NUMBER_FIELD("time", response_time)
  NUMBER_FIELD("response_time", response_time)
  BOOL_FIELD("failed", failed)
  BOOL_FIELD("cdn", cdn)

#undef STRING_FIELD
#undef NUMBER_FIELD
#undef BOOL_FIELD
  return v;
}

static bool condition_parse_operator(struct condition_parser *p,
                                     char *out,
                                     size_t out_len)
{
  static const char *ops[] = {
    "contains", "!contains", "==", "!=", ">=", "<=", ">", "<"
  };
  size_t i;

  condition_skip_ws(p);
  for(i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
    size_t len = strlen(ops[i]);
    if(!strncmp(p->s, ops[i], len)) {
      if(isalpha((unsigned char)ops[i][0]) &&
         (isalnum((unsigned char)p->s[len]) || p->s[len] == '_')) {
        continue;
      }
      if(len >= out_len)
        return false;
      memcpy(out, ops[i], len + 1);
      p->s += len;
      return true;
    }
  }
  return false;
}

static bool condition_parse_quoted(struct condition_parser *p,
                                   char *out,
                                   size_t out_len)
{
  char quote;
  size_t len = 0;

  condition_skip_ws(p);
  if(*p->s != '"' && *p->s != '\'')
    return false;
  quote = *p->s++;
  while(*p->s && *p->s != quote) {
    char ch = *p->s++;
    if(ch == '\\' && *p->s) {
      ch = *p->s++;
      if(ch == 'n')
        ch = '\n';
      else if(ch == 'r')
        ch = '\r';
      else if(ch == 't')
        ch = '\t';
    }
    if(len + 1 >= out_len)
      return false;
    out[len++] = ch;
  }
  if(*p->s != quote)
    return false;
  p->s++;
  out[len] = 0;
  return true;
}

static bool condition_parse_literal(struct condition_parser *p,
                                    struct condition_value *out,
                                    char *string_buf,
                                    size_t string_len)
{
  char *end = NULL;
  double number;
  size_t len = 0;

  memset(out, 0, sizeof(*out));
  out->type = COND_VALUE_MISSING;
  condition_skip_ws(p);
  if(condition_parse_quoted(p, string_buf, string_len)) {
    out->type = COND_VALUE_STRING;
    out->string = string_buf;
    return true;
  }
  if(condition_match_word(p, "true")) {
    out->type = COND_VALUE_BOOL;
    out->boolean = true;
    return true;
  }
  if(condition_match_word(p, "false")) {
    out->type = COND_VALUE_BOOL;
    out->boolean = false;
    return true;
  }

  errno = 0;
  number = strtod(p->s, &end);
  if(end != p->s && !errno) {
    out->type = COND_VALUE_NUMBER;
    out->number = number;
    p->s = end;
    return true;
  }

  while(p->s[len] && !isspace((unsigned char)p->s[len]) &&
        p->s[len] != ')' && p->s[len] != '(') {
    if(len + 1 >= string_len)
      return false;
    string_buf[len] = p->s[len];
    len++;
  }
  if(!len)
    return false;
  string_buf[len] = 0;
  p->s += len;
  out->type = COND_VALUE_STRING;
  out->string = string_buf;
  return true;
}

static const char *condition_value_string(const struct condition_value *v)
{
  if(v->type == COND_VALUE_STRING)
    return v->string ? v->string : "";
  if(v->type == COND_VALUE_BOOL)
    return v->boolean ? "true" : "false";
  return "";
}

static double condition_value_number(const struct condition_value *v)
{
  if(v->type == COND_VALUE_NUMBER)
    return v->number;
  if(v->type == COND_VALUE_BOOL)
    return v->boolean ? 1.0 : 0.0;
  return 0.0;
}

static bool condition_compare(const struct condition_value *left,
                              const char *op,
                              const struct condition_value *right)
{
  if(left->type == COND_VALUE_MISSING || right->type == COND_VALUE_MISSING)
    return false;
  if(!strcmp(op, "contains") || !strcmp(op, "!contains")) {
    bool found = contains_ci(condition_value_string(left),
                             condition_value_string(right));
    return op[0] == '!' ? !found : found;
  }
  if(left->type == COND_VALUE_STRING || right->type == COND_VALUE_STRING) {
    int cmp = strcmp(condition_value_string(left), condition_value_string(right));
    if(!strcmp(op, "=="))
      return cmp == 0;
    if(!strcmp(op, "!="))
      return cmp != 0;
    if(!strcmp(op, ">"))
      return cmp > 0;
    if(!strcmp(op, ">="))
      return cmp >= 0;
    if(!strcmp(op, "<"))
      return cmp < 0;
    if(!strcmp(op, "<="))
      return cmp <= 0;
    return false;
  }
  if(!strcmp(op, "=="))
    return condition_value_number(left) == condition_value_number(right);
  if(!strcmp(op, "!="))
    return condition_value_number(left) != condition_value_number(right);
  if(!strcmp(op, ">"))
    return condition_value_number(left) > condition_value_number(right);
  if(!strcmp(op, ">="))
    return condition_value_number(left) >= condition_value_number(right);
  if(!strcmp(op, "<"))
    return condition_value_number(left) < condition_value_number(right);
  if(!strcmp(op, "<="))
    return condition_value_number(left) <= condition_value_number(right);
  return false;
}

static bool condition_parse_expr(struct condition_parser *p);

static bool condition_parse_comparison(struct condition_parser *p)
{
  char field[64];
  char op[16];
  char literal[1024];
  struct condition_value left;
  struct condition_value right;

  if(!condition_parse_identifier(p, field, sizeof(field)) ||
     !condition_parse_operator(p, op, sizeof(op)) ||
     !condition_parse_literal(p, &right, literal, sizeof(literal))) {
    p->ok = false;
    return false;
  }
  if(p->validate_only) {
    struct cihx_result dummy;
    memset(&dummy, 0, sizeof(dummy));
    left = condition_field_value(&dummy, field);
    if(left.type == COND_VALUE_MISSING) {
      p->ok = false;
      return false;
    }
    return true;
  }
  left = condition_field_value(p->result, field);
  return condition_compare(&left, op, &right);
}

static bool condition_parse_factor(struct condition_parser *p)
{
  bool value;

  condition_skip_ws(p);
  if(*p->s == '(') {
    p->s++;
    value = condition_parse_expr(p);
    condition_skip_ws(p);
    if(*p->s != ')') {
      p->ok = false;
      return false;
    }
    p->s++;
    return value;
  }
  return condition_parse_comparison(p);
}

static bool condition_parse_term(struct condition_parser *p)
{
  bool value = condition_parse_factor(p);

  while(p->ok) {
    condition_skip_ws(p);
    if(strncmp(p->s, "&&", 2))
      break;
    p->s += 2;
    value = condition_parse_factor(p) && value;
  }
  return value;
}

static bool condition_parse_expr(struct condition_parser *p)
{
  bool value = condition_parse_term(p);

  while(p->ok) {
    condition_skip_ws(p);
    if(strncmp(p->s, "||", 2))
      break;
    p->s += 2;
    value = condition_parse_term(p) || value;
  }
  return value;
}

static bool condition_eval(const char *expr, const struct cihx_result *result)
{
  struct condition_parser p;
  bool value;

  if(!expr || !*expr)
    return true;
  p.s = expr;
  p.result = result;
  p.validate_only = false;
  p.ok = true;
  value = condition_parse_expr(&p);
  condition_skip_ws(&p);
  if(!p.ok || *p.s)
    return false;
  return value;
}

static bool condition_validate(const char *expr)
{
  struct condition_parser p;

  if(!expr || !*expr)
    return true;
  p.s = expr;
  p.result = NULL;
  p.validate_only = true;
  p.ok = true;
  (void)condition_parse_expr(&p);
  condition_skip_ws(&p);
  return p.ok && !*p.s;
}

static bool result_passes(const struct cihx_options *opts,
                          const struct cihx_result *r,
                          const char *raw)
{
  size_t i;

  if(opts->filter_status.len && intset_contains(&opts->filter_status, r->status_code))
    return false;
  if(opts->filter_length.len && intset_contains(&opts->filter_length, r->content_length))
    return false;
  if(opts->filter_lines.len && intset_contains(&opts->filter_lines, r->lines))
    return false;
  if(opts->filter_words.len && intset_contains(&opts->filter_words, r->words))
    return false;
  if(opts->filter_regexes.len && result_matches_regex_any(&opts->filter_regexes, raw))
    return false;
  for(i = 0; i < opts->filter_strings.len; i++) {
    if(contains_ci(raw, opts->filter_strings.items[i]))
      return false;
  }
  if(opts->filter_time.enabled && time_expr_matches(&opts->filter_time,
                                                    r->response_time))
    return false;
  if(opts->filter_cdn.len && strvec_contains_ci(&opts->filter_cdn, r->cdn_name))
    return false;
  if(opts->filter_condition && condition_eval(opts->filter_condition, r))
    return false;

  if(opts->match_status.len && !intset_contains(&opts->match_status, r->status_code))
    return false;
  if(opts->match_length.len && !intset_contains(&opts->match_length, r->content_length))
    return false;
  if(opts->match_lines.len && !intset_contains(&opts->match_lines, r->lines))
    return false;
  if(opts->match_words.len && !intset_contains(&opts->match_words, r->words))
    return false;
  if(opts->match_regexes.len && !result_matches_regex_all(&opts->match_regexes, raw))
    return false;
  if(opts->match_strings.len) {
    bool any = false;
    for(i = 0; i < opts->match_strings.len; i++) {
      if(contains_ci(raw, opts->match_strings.items[i])) {
        any = true;
        break;
      }
    }
    if(!any)
      return false;
  }
  if(opts->match_cdn.len && !strvec_contains_ci(&opts->match_cdn, r->cdn_name))
    return false;
  if(opts->match_time.enabled && !time_expr_matches(&opts->match_time,
                                                    r->response_time))
    return false;
  if(opts->match_condition && !condition_eval(opts->match_condition, r))
    return false;
  return true;
}

static int perform_once(const struct cihx_options *opts,
                        const char *start_url,
                        const char *input,
                        const char *method,
                        const char *host_ip,
                        struct result_owned *result)
{
  CURL *easy = NULL;
  CURLcode cc = CURLE_OK;
  struct capture cap;
  char *url = NULL;
  char *referer = NULL;
  int rc = CIHX_OK;
  long redirects = 0;
  double total_time = 0.0;

  memset(&cap, 0, sizeof(cap));
  cap.body.limit = opts->max_body_bytes;
  url = xstrdup(start_url);
  if(!url)
    return CIHX_ERR_NOMEM;

  for(;;) {
    struct curl_slist *headers = NULL;
    struct curl_slist *resolve = NULL;
    char *next_url = NULL;
    struct header_block *b;
    size_t body_start_len;
    double transfer_time = 0.0;
    long status;
    long attempt;

    body_start_len = cap.body.len;
    rc = capture_new_block(&cap, url);
    if(rc)
      break;
    b = &cap.blocks[cap.block_count - 1];

    for(attempt = 0; attempt <= opts->retries; attempt++) {
      easy = curl_easy_init();
      if(!easy) {
        rc = CIHX_ERR_CURL;
        break;
      }
      rc = setup_easy(easy, opts, url, method, referer, host_ip, &cap,
                      &headers, &resolve);
      if(rc) {
        curl_slist_free_all(headers);
        curl_slist_free_all(resolve);
        curl_easy_cleanup(easy);
        easy = NULL;
        break;
      }
      cc = curl_easy_perform(easy);
      (void)curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME, &transfer_time);
      if(!host_ip) {
        char *primary_ip = NULL;
        if(!curl_easy_getinfo(easy, CURLINFO_PRIMARY_IP, &primary_ip) &&
           primary_ip && *primary_ip) {
          snprintf(cap.primary_ip, sizeof(cap.primary_ip), "%s", primary_ip);
        }
      }
      total_time += transfer_time;
      curl_slist_free_all(headers);
      curl_slist_free_all(resolve);
      headers = NULL;
      resolve = NULL;
      curl_easy_cleanup(easy);
      easy = NULL;
      if(cc == CURLE_OK || attempt == opts->retries)
        break;

      cap.body.len = body_start_len;
      if(cap.body.data)
        cap.body.data[cap.body.len] = 0;
      header_block_free(b);
      memset(b, 0, sizeof(*b));
      b->url = xstrdup(url);
      if(!b->url) {
        rc = CIHX_ERR_NOMEM;
        break;
      }
    }
    if(rc)
      break;
    status = b->status;
    if(cc != CURLE_OK || !opts->follow_redirects ||
       status < 300 || status >= 400 || !b->location ||
       redirects >= opts->max_redirects)
      break;

    next_url = resolve_location(url, b->location);
    if(!next_url)
      break;
    if(opts->follow_host_redirects) {
      char *old_host = url_host(url);
      char *new_host = url_host(next_url);
      bool same_host = old_host && new_host && !strcasecmp(old_host, new_host);
      free(old_host);
      free(new_host);
      if(!same_host) {
        free(next_url);
        break;
      }
    }
    if(opts->auto_referer) {
      free(referer);
      referer = xstrdup(url);
      if(!referer) {
        free(next_url);
        rc = CIHX_ERR_NOMEM;
        break;
      }
    }
    free(url);
    url = next_url;
    redirects++;
  }

  if(!rc)
    rc = build_result(opts, input, method, url ? url : start_url, host_ip,
                      &cap, cc, total_time, result);
  if(easy)
    curl_easy_cleanup(easy);
  free(url);
  free(referer);
  capture_free(&cap);
  return rc;
}

static int emit_result(const struct cihx_options *opts,
                       struct result_owned *r,
                       cihx_result_cb cb,
                       void *userdata,
                       const char *raw,
                       bool emit_failed,
                       bool *emitted_success)
{
  int cb_rc = 0;

  if(emitted_success)
    *emitted_success = false;
  if(r->pub.failed && !emit_failed)
    return CIHX_OK;
  if(!result_passes(opts, &r->pub, raw))
    return CIHX_OK;
  if(opts->json_output) {
    int json_rc = cihx_result_write_json(opts->json_output, &r->pub);
    if(json_rc)
      return json_rc;
    fflush(opts->json_output);
  }
  if(cb)
    cb_rc = cb(&r->pub, userdata);
  if(!cb_rc && emitted_success && !r->pub.failed)
    *emitted_success = true;
  return cb_rc;
}

static int run_url(const struct cihx_options *opts,
                   const char *url,
                   const char *input,
                   const char *method,
                   const char *host_ip,
                   cihx_result_cb cb,
                   void *userdata,
                   bool emit_failed,
                   bool *emitted_success)
{
  struct result_owned r;
  struct buffer raw = {0};
  int rc;

  rc = perform_once(opts, url, input, method, host_ip, &r);
  if(rc)
    return rc;
  if(r.raw_header)
    (void)buffer_appendn(&raw, r.raw_header, strlen(r.raw_header));
  if(r.response_body)
    (void)buffer_appendn(&raw, r.response_body, strlen(r.response_body));
  rc = emit_result(opts, &r, cb, userdata, raw.data ? raw.data : "",
                   emit_failed, emitted_success);
  buffer_free(&raw);
  result_free(&r);
  return rc;
}

static bool port_applies(const struct port_spec *p, const char *scheme)
{
  return !p->scheme[0] || !strcasecmp(p->scheme, scheme);
}

static int run_expanded_url(const struct cihx_options *opts,
                            const char *target,
                            const char *scheme,
                            const char *path,
                            long port,
                            const char *method,
                            cihx_result_cb cb,
                            void *userdata,
                            bool emit_failed,
                            bool *emitted_success)
{
  char *base = NULL;
  char *with_path = NULL;
  char *with_port = NULL;
  int rc;

  base = make_base_url(scheme, target);
  if(!base)
    return CIHX_ERR_NOMEM;
  with_path = apply_path(base, path);
  free(base);
  if(!with_path)
    return CIHX_ERR_NOMEM;
  with_port = apply_port(with_path, port);
  free(with_path);
  if(!with_port)
    return CIHX_ERR_NOMEM;
  if(emitted_success)
    *emitted_success = false;
  if(opts->probe_all_ips) {
    struct strvec ips = {0};
    char *host = url_host(with_port);
    size_t i;

    rc = host ? resolve_host_ips(host, &ips) : CIHX_ERR_INVALID;
    if(!rc) {
      for(i = 0; i < ips.len; i++) {
        bool one_emitted_success = false;
        rc = run_url(opts, with_port, target, method, ips.items[i], cb,
                     userdata, emit_failed, &one_emitted_success);
        if(one_emitted_success && emitted_success)
          *emitted_success = true;
        if(rc)
          break;
      }
    }
    else {
      rc = run_url(opts, with_port, target, method, NULL, cb, userdata,
                   emit_failed, emitted_success);
    }
    free(host);
    strvec_free(&ips);
  }
  else {
    rc = run_url(opts, with_port, target, method, NULL, cb, userdata,
                 emit_failed, emitted_success);
  }
  free(with_port);
  return rc;
}

static int run_target_scheme(const struct cihx_options *opts,
                             const char *target,
                             const char *scheme,
                             const char *path,
                             const char *method,
                             cihx_result_cb cb,
                             void *userdata,
                             bool emit_failed,
                             bool ignore_port_scheme,
                             bool *emitted_success)
{
  size_t i;
  int rc = CIHX_OK;
  bool used_port = false;

  if(emitted_success)
    *emitted_success = false;
  for(i = 0; i < opts->port_count; i++) {
    if(ignore_port_scheme || port_applies(&opts->ports[i], scheme)) {
      bool one_emitted_success = false;
      used_port = true;
      rc = run_expanded_url(opts, target, scheme, path, opts->ports[i].port,
                            method, cb, userdata, emit_failed,
                            &one_emitted_success);
      if(one_emitted_success && emitted_success)
        *emitted_success = true;
      if(rc)
        return rc;
    }
  }
  if(!used_port)
    rc = run_expanded_url(opts, target, scheme, path, 0, method, cb, userdata,
                          emit_failed, emitted_success);
  return rc;
}

static long target_explicit_port(const char *target)
{
  char *base = NULL;
  char *port = NULL;
  CURLU *u;
  long out = 0;

  base = make_base_url("http", target);
  if(!base)
    return 0;
  u = curl_url();
  if(!u) {
    free(base);
    return 0;
  }
  if(!curl_url_set(u, CURLUPART_URL, base, 0) &&
     !curl_url_get(u, CURLUPART_PORT, &port, 0) && port && *port) {
    char *end = NULL;
    errno = 0;
    out = strtol(port, &end, 10);
    if(errno || end == port || *end)
      out = 0;
  }
  curl_free(port);
  curl_url_cleanup(u);
  free(base);
  return out;
}

static const char *preferred_default_scheme(const char *target)
{
  long port = target_explicit_port(target);

  if(port == 80 || port == 8080)
    return "http";
  if(port == 443)
    return "https";
  if(port > 1024)
    return "http";
  return "https";
}

static const char *preferred_scheme_for_port(long port, const char *target)
{
  if(port == 80 || port == 8080)
    return "http";
  if(port == 443)
    return "https";
  if(port > 1024)
    return "http";
  return preferred_default_scheme(target);
}

static char *fallback_target_for_scheme(const char *target,
                                        const char *from_scheme,
                                        const char *to_scheme)
{
  long port = target_explicit_port(target);
  const char *new_port = NULL;
  char *base = NULL;
  CURLU *u;
  char *url = NULL;
  char *out = NULL;
  size_t prefix_len;

  if(!strcmp(from_scheme, "https") && !strcmp(to_scheme, "http") &&
     port == 443) {
    new_port = "80";
  }
  else if(!strcmp(from_scheme, "http") && !strcmp(to_scheme, "https") &&
          port == 80) {
    new_port = "443";
  }
  else {
    return xstrdup(target);
  }

  base = make_base_url(to_scheme, target);
  if(!base)
    return NULL;
  u = curl_url();
  if(!u) {
    free(base);
    return NULL;
  }
  if(!curl_url_set(u, CURLUPART_URL, base, 0) &&
     !curl_url_set(u, CURLUPART_PORT, new_port, 0) &&
     !curl_url_get(u, CURLUPART_URL, &url, 0)) {
    prefix_len = strlen(to_scheme) + 3;
    out = xstrdup(!strncmp(url, to_scheme, strlen(to_scheme)) &&
                  url[strlen(to_scheme)] == ':' ? url + prefix_len : url);
  }
  curl_free(url);
  curl_url_cleanup(u);
  free(base);
  return out;
}

static int run_custom_ports(const struct cihx_options *opts,
                            const char *target,
                            const char *forced_scheme,
                            const char *path,
                            const char *method,
                            cihx_result_cb cb,
                            void *userdata)
{
  size_t i;
  int rc = CIHX_OK;

  for(i = 0; i < opts->port_count; i++) {
    const struct port_spec *p = &opts->ports[i];

    if(forced_scheme) {
      rc = run_expanded_url(opts, target, forced_scheme, path, p->port,
                            method, cb, userdata, true, NULL);
    }
    else if(p->scheme[0]) {
      rc = run_expanded_url(opts, target, p->scheme, path, p->port, method,
                            cb, userdata, true, NULL);
    }
    else if(opts->no_fallback) {
      rc = run_expanded_url(opts, target, "https", path, p->port, method,
                            cb, userdata, true, NULL);
      if(!rc)
        rc = run_expanded_url(opts, target, "http", path, p->port, method,
                              cb, userdata, true, NULL);
    }
    else {
      const char *first = preferred_scheme_for_port(p->port, target);
      const char *second = !strcmp(first, "https") ? "http" : "https";
      bool emitted_success = false;

      rc = run_expanded_url(opts, target, first, path, p->port, method, cb,
                            userdata, false, &emitted_success);
      if(!rc && !emitted_success)
        rc = run_expanded_url(opts, target, second, path, p->port, method, cb,
                              userdata, true, NULL);
    }
    if(rc)
      return rc;
  }
  return rc;
}

static int run_target_path_method(const struct cihx_options *opts,
                                  const char *target,
                                  const char *path,
                                  const char *method,
                                  cihx_result_cb cb,
                                  void *userdata)
{
  char *scheme = NULL;
  int rc = CIHX_OK;

  if(has_scheme(target)) {
    scheme = url_scheme(target);
    if(!scheme)
      return CIHX_ERR_INVALID;
    if(opts->port_count) {
      rc = run_custom_ports(opts, target,
                            opts->no_fallback_scheme ? scheme : NULL,
                            path, method, cb, userdata);
    }
    else {
      rc = run_target_scheme(opts, target, scheme, path, method, cb, userdata,
                             true, false, NULL);
    }
    free(scheme);
    return rc;
  }

  if(opts->port_count) {
    rc = run_custom_ports(opts, target,
                          opts->no_fallback_scheme ? opts->default_scheme :
                          NULL,
                          path, method, cb, userdata);
  }
  else if(opts->no_fallback_scheme) {
    rc = run_target_scheme(opts, target, opts->default_scheme, path, method,
                           cb, userdata, true, false, NULL);
  }
  else if(opts->no_fallback) {
    rc = run_target_scheme(opts, target, "https", path, method, cb, userdata,
                           true, false, NULL);
    if(rc)
      return rc;
    rc = run_target_scheme(opts, target, "http", path, method, cb, userdata,
                           true, false, NULL);
  }
  else {
    const char *first = preferred_default_scheme(target);
    const char *second = !strcmp(first, "https") ? "http" : "https";
    char *fallback_target = NULL;
    bool emitted_success = false;

    rc = run_target_scheme(opts, target, first, path, method, cb, userdata,
                           false, false, &emitted_success);
    if(rc)
      return rc;
    if(!emitted_success) {
      fallback_target = fallback_target_for_scheme(target, first, second);
      if(!fallback_target)
        return CIHX_ERR_NOMEM;
      rc = run_target_scheme(opts, fallback_target, second, path, method, cb,
                             userdata, true, false, NULL);
      free(fallback_target);
    }
  }
  return rc;
}

int cihx_run(const cihx_options *opts, cihx_result_cb callback, void *userdata)
{
  size_t ti;
  size_t pi;
  size_t mi;
  int rc;

  if(!opts || opts->targets.len == 0)
    return CIHX_ERR_INVALID;
  rc = (int)curl_global_init(CURL_GLOBAL_DEFAULT);
  if(rc)
    return CIHX_ERR_CURL;
  srand((unsigned int)(time(NULL) ^ (time_t)getpid()));
  for(ti = 0; ti < opts->targets.len; ti++) {
    for(pi = 0; pi < (opts->paths.len ? opts->paths.len : 1); pi++) {
      const char *path = opts->paths.len ? opts->paths.items[pi] : NULL;
      for(mi = 0; mi < opts->methods.len; mi++) {
        rc = run_target_path_method(opts, opts->targets.items[ti], path,
                                    opts->methods.items[mi], callback,
                                    userdata);
        if(rc)
          goto out;
      }
    }
  }
out:
  curl_global_cleanup();
  return rc;
}

cihx_options *cihx_options_new(void)
{
  cihx_options *opts = xcalloc(1, sizeof(*opts));
  if(!opts)
    return NULL;
  opts->probe_flags = CIHX_PROBE_DEFAULTS | CIHX_PROBE_CDN;
  opts->body_preview_size = CIHX_DEFAULT_BODY_PREVIEW;
  opts->max_body_bytes = CIHX_DEFAULT_MAX_BODY;
  opts->max_redirects = CIHX_DEFAULT_REDIRECTS;
  opts->timeout_seconds = CIHX_DEFAULT_TIMEOUT;
  opts->random_agent = true;
  opts->default_scheme = xstrdup("https");
  if(!opts->default_scheme || strvec_push(&opts->methods, "GET")) {
    cihx_options_free(opts);
    return NULL;
  }
  return opts;
}

void cihx_options_free(cihx_options *opts)
{
  size_t i;

  if(!opts)
    return;
  strvec_free(&opts->targets);
  strvec_free(&opts->paths);
  strvec_free(&opts->headers);
  strvec_free(&opts->resolvers);
  strvec_free(&opts->match_strings);
  strvec_free(&opts->filter_strings);
  strvec_free(&opts->match_cdn);
  strvec_free(&opts->filter_cdn);
  strvec_free(&opts->methods);
  regexvec_free(&opts->match_regexes);
  regexvec_free(&opts->filter_regexes);
  regexvec_free(&opts->extract_regexes);
  intset_free(&opts->match_status);
  intset_free(&opts->match_length);
  intset_free(&opts->match_lines);
  intset_free(&opts->match_words);
  intset_free(&opts->filter_status);
  intset_free(&opts->filter_length);
  intset_free(&opts->filter_lines);
  intset_free(&opts->filter_words);
  for(i = 0; i < opts->port_count; i++)
    free(opts->ports[i].scheme);
  free(opts->ports);
  free(opts->proxy);
  free(opts->body);
  free(opts->default_scheme);
  free(opts->ports_expr);
  free(opts->match_condition);
  free(opts->filter_condition);
  free(opts);
}

int cihx_options_add_target(cihx_options *opts, const char *target)
{
  return opts ? add_csv_values(&opts->targets, target) : CIHX_ERR_INVALID;
}

int cihx_options_add_targets_file(cihx_options *opts, const char *path)
{
  return opts ? read_lines_into(path, &opts->targets) : CIHX_ERR_INVALID;
}

int cihx_options_add_path(cihx_options *opts, const char *path_or_file)
{
  return opts ? add_csv_or_file(&opts->paths, path_or_file) : CIHX_ERR_INVALID;
}

int cihx_options_add_header(cihx_options *opts, const char *header)
{
  return opts ? strvec_push_trimmed(&opts->headers, header) : CIHX_ERR_INVALID;
}

int cihx_options_add_resolver(cihx_options *opts, const char *resolver)
{
  return opts ? add_csv_or_file(&opts->resolvers, resolver) : CIHX_ERR_INVALID;
}

int cihx_options_add_match_string(cihx_options *opts, const char *value)
{
  return opts ? add_csv_values(&opts->match_strings, value) :
                CIHX_ERR_INVALID;
}

int cihx_options_add_match_regex(cihx_options *opts, const char *value)
{
  return opts ? regexvec_add_csv(&opts->match_regexes, value) :
                CIHX_ERR_INVALID;
}

int cihx_options_add_match_cdn(cihx_options *opts, const char *value)
{
  return opts ? add_csv_values(&opts->match_cdn, value) : CIHX_ERR_INVALID;
}

int cihx_options_add_filter_cdn(cihx_options *opts, const char *value)
{
  return opts ? add_csv_values(&opts->filter_cdn, value) : CIHX_ERR_INVALID;
}

int cihx_options_add_filter_string(cihx_options *opts, const char *value)
{
  return opts ? add_csv_values(&opts->filter_strings, value) :
                CIHX_ERR_INVALID;
}

int cihx_options_add_filter_regex(cihx_options *opts, const char *value)
{
  return opts ? regexvec_add_csv(&opts->filter_regexes, value) :
                CIHX_ERR_INVALID;
}

int cihx_options_add_extract_regex(cihx_options *opts, const char *value)
{
  if(!opts)
    return CIHX_ERR_INVALID;
  return regexvec_add(&opts->extract_regexes, value);
}

static bool is_http_token_char(unsigned char c)
{
  return isalnum(c) || c == '!' || c == '#' || c == '$' || c == '%' ||
         c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' ||
         c == '.' || c == '^' || c == '_' || c == '`' || c == '|' ||
         c == '~';
}

static bool is_valid_method_token(const char *method)
{
  const unsigned char *p = (const unsigned char *)method;

  if(!method || !*method)
    return false;
  for(; *p; p++) {
    if(!is_http_token_char(*p))
      return false;
  }
  return true;
}

static int methods_add_all(struct strvec *methods)
{
  int rc;

  strvec_free(methods);
  rc = strvec_push(methods, "GET");
  if(!rc) rc = strvec_push(methods, "POST");
  if(!rc) rc = strvec_push(methods, "PUT");
  if(!rc) rc = strvec_push(methods, "DELETE");
  if(!rc) rc = strvec_push(methods, "PATCH");
  if(!rc) rc = strvec_push(methods, "HEAD");
  if(!rc) rc = strvec_push(methods, "OPTIONS");
  return rc;
}

static int method_add_one(struct strvec *methods, char *method)
{
  char *p;

  if(!strcasecmp(method, "all"))
    return methods_add_all(methods);
  for(p = method; *p; p++)
    *p = (char)toupper((unsigned char)*p);
  if(!is_valid_method_token(method))
    return CIHX_ERR_INVALID;
  return strvec_push(methods, method);
}

int cihx_options_add_method(cihx_options *opts, const char *method)
{
  char *copy;
  char *cursor;
  struct strvec parsed;
  bool saw_value = false;
  int rc = CIHX_OK;

  if(!opts || !method)
    return CIHX_ERR_INVALID;
  if(opts->methods_explicit)
    rc = strvec_clone(&parsed, &opts->methods);
  else
    memset(&parsed, 0, sizeof(parsed));
  if(rc)
    return rc;
  copy = xstrdup(method);
  if(!copy) {
    strvec_free(&parsed);
    return CIHX_ERR_NOMEM;
  }
  cursor = copy;
  for(;;) {
    char *comma = strchr(cursor, ',');
    char *trimmed;
    if(comma)
      *comma = 0;
    trimmed = trim_in_place(cursor);
    if(!*trimmed) {
      rc = CIHX_ERR_INVALID;
      break;
    }
    saw_value = true;
    rc = method_add_one(&parsed, trimmed);
    if(rc)
      break;
    if(!comma)
      break;
    cursor = comma + 1;
  }
  if(!saw_value)
    rc = CIHX_ERR_INVALID;
  free(copy);
  if(rc) {
    strvec_free(&parsed);
    return rc;
  }
  strvec_free(&opts->methods);
  opts->methods = parsed;
  opts->methods_explicit = true;
  return rc;
}

void cihx_options_set_probe_flags(cihx_options *opts, unsigned int flags)
{
  if(opts)
    opts->probe_flags = flags;
}

void cihx_options_set_tech_detect(cihx_options *opts, bool enabled)
{
  if(!opts)
    return;
  if(enabled)
    opts->probe_flags |= CIHX_PROBE_TECH_DETECT;
  else
    opts->probe_flags &= ~CIHX_PROBE_TECH_DETECT;
}

void cihx_options_set_json_output(cihx_options *opts, FILE *fp)
{
  if(opts)
    opts->json_output = fp;
}

void cihx_options_set_include_response_header(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->include_response_header = enabled;
}

void cihx_options_set_include_response(cihx_options *opts, bool enabled)
{
  if(opts) {
    opts->include_response = enabled;
    if(enabled)
      opts->include_response_header = true;
  }
}

void cihx_options_set_include_chain(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->include_chain = enabled;
}

int cihx_options_set_body_preview_size(cihx_options *opts, size_t size)
{
  if(!opts)
    return CIHX_ERR_INVALID;
  opts->body_preview_size = size;
  return CIHX_OK;
}

static void replace_string(char **slot, const char *value);

static int set_number_expr(struct intset *slot, const char *expr)
{
  struct intset parsed;
  int rc;

  memset(&parsed, 0, sizeof(parsed));
  rc = parse_number_list(expr, &parsed);
  if(rc) {
    intset_free(&parsed);
    return rc;
  }
  intset_free(slot);
  *slot = parsed;
  return CIHX_OK;
}

static int set_time_expr(struct time_expr *slot, const char *expr)
{
  struct time_expr parsed;
  int rc;

  rc = parse_time_expr(expr, &parsed);
  if(rc)
    return rc;
  *slot = parsed;
  return CIHX_OK;
}

int cihx_options_set_match_status_code(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->match_status, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_match_content_length(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->match_length, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_match_line_count(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->match_lines, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_match_word_count(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->match_words, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_match_response_time(cihx_options *opts, const char *expr)
{
  return opts ? set_time_expr(&opts->match_time, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_match_condition(cihx_options *opts, const char *expr)
{
  if(!opts || !condition_validate(expr))
    return CIHX_ERR_INVALID;
  replace_string(&opts->match_condition, expr);
  return expr && !opts->match_condition ? CIHX_ERR_NOMEM : CIHX_OK;
}

int cihx_options_set_filter_status_code(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->filter_status, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_filter_content_length(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->filter_length, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_filter_line_count(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->filter_lines, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_filter_word_count(cihx_options *opts, const char *expr)
{
  return opts ? set_number_expr(&opts->filter_words, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_filter_response_time(cihx_options *opts, const char *expr)
{
  return opts ? set_time_expr(&opts->filter_time, expr) : CIHX_ERR_INVALID;
}

int cihx_options_set_filter_condition(cihx_options *opts, const char *expr)
{
  if(!opts || !condition_validate(expr))
    return CIHX_ERR_INVALID;
  replace_string(&opts->filter_condition, expr);
  return expr && !opts->filter_condition ? CIHX_ERR_NOMEM : CIHX_OK;
}

void cihx_options_set_extract_presets(cihx_options *opts, unsigned int presets)
{
  if(opts)
    opts->extract_presets = presets;
}

static void replace_string(char **slot, const char *value)
{
  char *copy = value ? xstrdup(value) : NULL;
  free(*slot);
  *slot = copy;
}

void cihx_options_set_proxy(cihx_options *opts, const char *proxy)
{
  if(opts)
    replace_string(&opts->proxy, proxy);
}

void cihx_options_set_body(cihx_options *opts, const char *body)
{
  if(opts)
    replace_string(&opts->body, body);
}

void cihx_options_set_follow_redirects(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->follow_redirects = enabled;
}

void cihx_options_set_follow_host_redirects(cihx_options *opts, bool enabled)
{
  if(opts) {
    opts->follow_host_redirects = enabled;
    if(enabled)
      opts->follow_redirects = true;
  }
}

int cihx_options_set_max_redirects(cihx_options *opts, long max_redirects)
{
  if(!opts || max_redirects < 0)
    return CIHX_ERR_INVALID;
  opts->max_redirects = max_redirects;
  return CIHX_OK;
}

int cihx_options_set_timeout(cihx_options *opts, long seconds)
{
  if(!opts || seconds <= 0)
    return CIHX_ERR_INVALID;
  opts->timeout_seconds = seconds;
  return CIHX_OK;
}

int cihx_options_set_retries(cihx_options *opts, long retries)
{
  if(!opts || retries < 0)
    return CIHX_ERR_INVALID;
  opts->retries = retries;
  return CIHX_OK;
}

void cihx_options_set_no_fallback(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->no_fallback = enabled;
}

void cihx_options_set_no_fallback_scheme(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->no_fallback_scheme = enabled;
}

void cihx_options_set_random_agent(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->random_agent = enabled;
}

int cihx_options_set_default_scheme(cihx_options *opts, const char *scheme)
{
  char normalized[6];
  size_t i;

  if(!opts || !scheme)
    return CIHX_ERR_INVALID;
  for(i = 0; scheme[i]; i++) {
    if(i + 1 >= sizeof(normalized))
      return CIHX_ERR_INVALID;
    normalized[i] = (char)tolower((unsigned char)scheme[i]);
  }
  normalized[i] = 0;
  if(strcmp(normalized, "http") && strcmp(normalized, "https"))
    return CIHX_ERR_INVALID;
  replace_string(&opts->default_scheme, normalized);
  return opts->default_scheme ? CIHX_OK : CIHX_ERR_NOMEM;
}

void cihx_options_set_auto_referer(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->auto_referer = enabled;
}

static void clear_ports(cihx_options *opts)
{
  size_t i;

  for(i = 0; i < opts->port_count; i++)
    free(opts->ports[i].scheme);
  free(opts->ports);
  opts->ports = NULL;
  opts->port_count = 0;
  opts->port_cap = 0;
}

int cihx_options_set_ports(cihx_options *opts, const char *ports)
{
  struct cihx_options parsed;
  int rc;

  if(!opts)
    return CIHX_ERR_INVALID;
  memset(&parsed, 0, sizeof(parsed));
  rc = parse_ports(&parsed, ports);
  if(rc) {
    clear_ports(&parsed);
    return rc;
  }
  clear_ports(opts);
  opts->ports = parsed.ports;
  opts->port_count = parsed.port_count;
  opts->port_cap = parsed.port_cap;
  parsed.ports = NULL;
  parsed.port_count = 0;
  parsed.port_cap = 0;
  replace_string(&opts->ports_expr, ports);
  return CIHX_OK;
}

void cihx_options_set_max_body_bytes(cihx_options *opts, size_t bytes)
{
  if(opts)
    opts->max_body_bytes = bytes;
}

void cihx_options_set_probe_all_ips(cihx_options *opts, bool enabled)
{
  if(opts)
    opts->probe_all_ips = enabled;
}

const char *cihx_strerror(int code)
{
  switch(code) {
  case CIHX_OK:
    return "ok";
  case CIHX_ERR_INVALID:
    return "invalid argument";
  case CIHX_ERR_NOMEM:
    return "out of memory";
  case CIHX_ERR_CURL:
    return "curl error";
  case CIHX_ERR_IO:
    return "i/o error";
  default:
    return "unknown error";
  }
}
