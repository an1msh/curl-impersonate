# httpx-like output usage

This repository includes `httpxlib`, a high-level C helper layer for producing
httpx-style probe results on top of libcurl/libcurl-impersonate.

Use it when you want curl-impersonate as a library, but with httpx-style input
handling, probing, matching, filtering, extraction, redirect-chain capture, and
JSONL output.

## Build and link

Build the helper library:

```sh
make -C httpxlib
```

Include the public API:

```c
#include "ci_httpx.h"
```

Link your program with the helper library and libcurl:

```sh
cc -Ihttpxlib your_program.c httpxlib/libci_httpx.a -lcurl -o your_program
```

If you need browser impersonation behavior, link against the curl-impersonate
libcurl build you normally use, or run with the relevant `LD_PRELOAD` setup.

## Minimal JSONL usage

Use `cihx_options_set_json_output()` when you want the library to write
httpx-like JSONL directly.

```c
#include "ci_httpx.h"

#include <stdio.h>

int main(void)
{
  cihx_options *opts = cihx_options_new();
  int rc = 0;

  if(!opts)
    return 1;

  rc = cihx_options_add_target(opts, "https://example.com");
  if(!rc)
    rc = cihx_options_set_match_status_code(opts, "200,301-302");

  cihx_options_set_include_response_header(opts, true);
  cihx_options_set_tech_detect(opts, true);
  cihx_options_set_json_output(opts, stdout);

  if(!rc)
    rc = cihx_run(opts, NULL, NULL);

  if(rc)
    fprintf(stderr, "cihx failed: %s\n", cihx_strerror(rc));

  cihx_options_free(opts);
  return rc ? 1 : 0;
}
```

## Callback usage

Use a callback when you want to inspect each result in-process. If you still
want the same JSON schema, call `cihx_result_write_json()`.

```c
#include "ci_httpx.h"

#include <stdio.h>

static int on_result(const cihx_result *r, void *userdata)
{
  FILE *jsonl = userdata;

  printf("%s %ld %s\n", r->url, r->status_code, r->title);
  return cihx_result_write_json(jsonl, r);
}

int main(void)
{
  cihx_options *opts = cihx_options_new();
  int rc = 0;

  if(!opts)
    return 1;

  rc = cihx_options_add_target(opts, "example.com");
  if(!rc)
    rc = cihx_options_set_default_scheme(opts, "https");
  if(!rc)
    rc = cihx_options_add_path(opts, "/,/login,/admin");
  if(!rc)
    rc = cihx_options_add_filter_string(opts, "not found,forbidden");

  cihx_options_set_no_fallback_scheme(opts, true);
  cihx_options_set_include_response_header(opts, true);

  if(!rc)
    rc = cihx_run(opts, on_result, stdout);

  if(rc)
    fprintf(stderr, "cihx failed: %s\n", cihx_strerror(rc));

  cihx_options_free(opts);
  return rc ? 1 : 0;
}
```

The `cihx_result *` passed to the callback is owned by the library and is only
valid during that callback.

## Common option groups

Input:

- `cihx_options_add_target(opts, "example.com,https://example.org")`
- `cihx_options_add_targets_file(opts, "targets.txt")`
- `cihx_options_add_path(opts, "/,/api,/health")`
- `cihx_options_set_ports(opts, "http:80,8080-8082,https:443")`

Output detail:

- `cihx_options_set_json_output(opts, fp)` writes JSONL directly.
- `cihx_result_write_json(fp, result)` writes one callback result as JSON.
- `cihx_options_set_include_response_header(opts, true)` includes headers.
- `cihx_options_set_include_response(opts, true)` includes headers, request, and body.
- `cihx_options_set_include_chain(opts, true)` includes redirect chain data.
- `cihx_options_set_tech_detect(opts, true)` includes detected technologies.

Matchers and filters:

- `cihx_options_set_match_status_code(opts, "200,301-302")`
- `cihx_options_set_filter_status_code(opts, "403,404")`
- `cihx_options_add_match_string(opts, "admin,login")`
- `cihx_options_add_filter_string(opts, "not found,forbidden")`
- `cihx_options_add_match_regex(opts, "hello,admin")`
- `cihx_options_add_filter_regex(opts, "error,denied")`
- `cihx_options_add_match_cdn(opts, "cloudflare,fastly")`
- `cihx_options_add_filter_cdn(opts, "akamai")`
- `cihx_options_set_match_response_time(opts, "< 1s")`
- `cihx_options_set_filter_response_time(opts, "> 2s")`
- `cihx_options_set_match_condition(opts, "status_code == 200 && cdn == false")`
- `cihx_options_set_filter_condition(opts, "failed == true")`

Extraction:

- `cihx_options_add_extract_regex(opts, "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")`
- `cihx_options_set_extract_presets(opts, CIHX_EXTRACT_PRESET_URL | CIHX_EXTRACT_PRESET_IPV4 | CIHX_EXTRACT_PRESET_MAIL)`

Request behavior:

- `cihx_options_add_header(opts, "User-Agent: custom-agent")`
- `cihx_options_add_method(opts, "GET,POST")`
- `cihx_options_set_body(opts, "{\"probe\":true}")`
- `cihx_options_set_proxy(opts, "http://127.0.0.1:8080")`
- `cihx_options_set_follow_redirects(opts, true)`
- `cihx_options_set_follow_host_redirects(opts, true)`
- `cihx_options_set_max_redirects(opts, 10)`
- `cihx_options_set_auto_referer(opts, true)`
- `cihx_options_set_probe_all_ips(opts, true)`
- `cihx_options_add_resolver(opts, "1.1.1.1,8.8.8.8")`
- `cihx_options_set_timeout(opts, 10)`
- `cihx_options_set_retries(opts, 1)`

## Error handling

Configuration functions that parse user input return an `int` status code.
Check those return values before running:

```c
int rc = cihx_options_set_ports(opts, "http:80,https:443");
if(rc) {
  fprintf(stderr, "invalid config: %s\n", cihx_strerror(rc));
  return 1;
}
```

## Mental model

Create `cihx_options`, add inputs and httpx-like behavior, choose either direct
JSONL output or a callback, then call `cihx_run()`. Free the options object when
finished.
