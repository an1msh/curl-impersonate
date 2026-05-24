/*
 * High-level httpx-style probing API for libcurl-impersonate.
 *
 * This layer intentionally sits above libcurl.  It does not change curl's TLS
 * or HTTP fingerprinting behavior; callers should link it with, or preload,
 * libcurl-impersonate when browser impersonation is required.
 */
#ifndef CI_HTTPX_H
#define CI_HTTPX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cihx_options cihx_options;
typedef struct cihx_result cihx_result;

typedef int (*cihx_result_cb)(const cihx_result *result, void *userdata);

enum cihx_probe_flag {
  CIHX_PROBE_STATUS_CODE    = 1u << 0,
  CIHX_PROBE_CONTENT_LENGTH = 1u << 1,
  CIHX_PROBE_CONTENT_TYPE   = 1u << 2,
  CIHX_PROBE_LOCATION       = 1u << 3,
  CIHX_PROBE_LINE_COUNT     = 1u << 4,
  CIHX_PROBE_WORD_COUNT     = 1u << 5,
  CIHX_PROBE_TITLE          = 1u << 6,
  CIHX_PROBE_BODY_PREVIEW   = 1u << 7,
  CIHX_PROBE_WEB_SERVER     = 1u << 8,
  CIHX_PROBE_CDN            = 1u << 9,
  CIHX_PROBE_TECH_DETECT    = 1u << 10,
  CIHX_PROBE_DEFAULTS       = CIHX_PROBE_STATUS_CODE |
                              CIHX_PROBE_CONTENT_LENGTH |
                              CIHX_PROBE_CONTENT_TYPE |
                              CIHX_PROBE_LOCATION |
                              CIHX_PROBE_LINE_COUNT |
                              CIHX_PROBE_WORD_COUNT |
                              CIHX_PROBE_TITLE |
                              CIHX_PROBE_BODY_PREVIEW |
                              CIHX_PROBE_WEB_SERVER
};

enum cihx_extract_preset {
  CIHX_EXTRACT_PRESET_URL  = 1u << 0,
  CIHX_EXTRACT_PRESET_IPV4 = 1u << 1,
  CIHX_EXTRACT_PRESET_MAIL = 1u << 2
};

struct cihx_header {
  const char *name;
  const char *value;
};

struct cihx_chain_item {
  const char *url;
  long status_code;
  const char *location;
  const char *request_url;
  const char *request;
  const char *response;
  const char *raw_header;
};

struct cihx_extract_item {
  const char *name;
  const char *value;
};

struct cihx_result {
  const char *url;
  const char *input;
  const char *final_url;
  const char *scheme;
  const char *host;
  const char *host_ip;
  const char *port;
  const char *path;
  const char *method;
  const char *location;
  const char *title;
  const char *webserver;
  const char *content_type;
  const char *body_preview;
  const char *response_body;
  const char *raw_header;
  const char *request;
  const char *error;
  const char *cdn_name;
  const char *cdn_type;
  const char *tech;
  const struct cihx_header *headers;
  size_t header_count;
  const struct cihx_chain_item *chain;
  size_t chain_count;
  const long *chain_status_codes;
  size_t chain_status_code_count;
  const struct cihx_extract_item *extracts;
  size_t extract_count;
  long status_code;
  long content_length;
  long words;
  long lines;
  double response_time;
  bool failed;
  bool cdn;
};

cihx_options *cihx_options_new(void);
void cihx_options_free(cihx_options *opts);

int cihx_options_add_target(cihx_options *opts, const char *target);
int cihx_options_add_targets_file(cihx_options *opts, const char *path);
int cihx_options_add_path(cihx_options *opts, const char *path_or_file);
int cihx_options_add_header(cihx_options *opts, const char *header);
int cihx_options_add_resolver(cihx_options *opts, const char *resolver);
int cihx_options_add_match_string(cihx_options *opts, const char *value);
int cihx_options_add_match_regex(cihx_options *opts, const char *value);
int cihx_options_add_match_cdn(cihx_options *opts, const char *value);
int cihx_options_add_filter_string(cihx_options *opts, const char *value);
int cihx_options_add_filter_regex(cihx_options *opts, const char *value);
int cihx_options_add_filter_cdn(cihx_options *opts, const char *value);
int cihx_options_add_extract_regex(cihx_options *opts, const char *value);
int cihx_options_add_method(cihx_options *opts, const char *method);

void cihx_options_set_probe_flags(cihx_options *opts, unsigned int flags);
void cihx_options_set_tech_detect(cihx_options *opts, bool enabled);
void cihx_options_set_json_output(cihx_options *opts, FILE *fp);
void cihx_options_set_include_response_header(cihx_options *opts, bool enabled);
void cihx_options_set_include_response(cihx_options *opts, bool enabled);
void cihx_options_set_include_chain(cihx_options *opts, bool enabled);
int cihx_options_set_body_preview_size(cihx_options *opts, size_t size);
int cihx_options_set_match_status_code(cihx_options *opts, const char *expr);
int cihx_options_set_match_content_length(cihx_options *opts, const char *expr);
int cihx_options_set_match_line_count(cihx_options *opts, const char *expr);
int cihx_options_set_match_word_count(cihx_options *opts, const char *expr);
int cihx_options_set_match_response_time(cihx_options *opts, const char *expr);
int cihx_options_set_match_condition(cihx_options *opts, const char *expr);
int cihx_options_set_filter_status_code(cihx_options *opts, const char *expr);
int cihx_options_set_filter_content_length(cihx_options *opts, const char *expr);
int cihx_options_set_filter_line_count(cihx_options *opts, const char *expr);
int cihx_options_set_filter_word_count(cihx_options *opts, const char *expr);
int cihx_options_set_filter_response_time(cihx_options *opts, const char *expr);
int cihx_options_set_filter_condition(cihx_options *opts, const char *expr);
void cihx_options_set_extract_presets(cihx_options *opts, unsigned int presets);
void cihx_options_set_proxy(cihx_options *opts, const char *proxy);
void cihx_options_set_body(cihx_options *opts, const char *body);
void cihx_options_set_follow_redirects(cihx_options *opts, bool enabled);
void cihx_options_set_follow_host_redirects(cihx_options *opts, bool enabled);
int cihx_options_set_max_redirects(cihx_options *opts, long max_redirects);
int cihx_options_set_timeout(cihx_options *opts, long seconds);
int cihx_options_set_retries(cihx_options *opts, long retries);
void cihx_options_set_no_fallback(cihx_options *opts, bool enabled);
void cihx_options_set_no_fallback_scheme(cihx_options *opts, bool enabled);
void cihx_options_set_random_agent(cihx_options *opts, bool enabled);
int cihx_options_set_default_scheme(cihx_options *opts, const char *scheme);
void cihx_options_set_auto_referer(cihx_options *opts, bool enabled);
int cihx_options_set_ports(cihx_options *opts, const char *ports);
void cihx_options_set_max_body_bytes(cihx_options *opts, size_t bytes);
void cihx_options_set_probe_all_ips(cihx_options *opts, bool enabled);

int cihx_result_write_json(FILE *fp, const cihx_result *result);
int cihx_run(const cihx_options *opts, cihx_result_cb callback, void *userdata);
const char *cihx_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif
