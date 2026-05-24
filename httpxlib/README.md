# httpx-style library layer

`httpxlib` is a small high-level C API for using libcurl/libcurl-impersonate
with httpx-style probing, JSONL output, matchers, filters, extractors, path and
port expansion, manual redirects, and request configuration.

It does not change curl's impersonation internals. Link the static helper with
the libcurl variant you want to use, or run with `LD_PRELOAD` pointing at
`libcurl-impersonate`.

## Build

```sh
make -C httpxlib
```

This builds:

- `httpxlib/libci_httpx.a` - reusable library layer
- `httpxlib/ci-httpx` - thin verification CLI around the library

## Minimal API Usage

```c
#include "ci_httpx.h"

static int on_result(const cihx_result *result, void *userdata)
{
  FILE *jsonl = userdata;
  printf("%s %ld\n", result->url, result->status_code);
  return cihx_result_write_json(jsonl, result);
}

int main(void)
{
  cihx_options *opts = cihx_options_new();
  cihx_options_add_target(opts, "example.com");
  cihx_options_set_default_scheme(opts, "https");
  cihx_options_set_no_fallback_scheme(opts, true);
  if(cihx_options_set_match_status_code(opts, "200,301-302"))
    return 1;
  cihx_options_set_match_condition(opts, "status_code == 200 && cdn == false");
  cihx_options_set_include_response_header(opts, true);
  cihx_options_set_probe_all_ips(opts, true);
  cihx_options_set_random_agent(opts, true);
  cihx_options_set_tech_detect(opts, true);
  int rc = cihx_run(opts, on_result, stdout);
  cihx_options_free(opts);
  return rc == 0 ? 0 : 1;
}
```

The callback result is owned by the library and is valid only for the duration
of the callback. Callback consumers can serialize exactly the same JSONL schema
as the CLI with `cihx_result_write_json`. If you want the library to emit JSONL
without a callback, configure `cihx_options_set_json_output` before calling
`cihx_run`.

`cihx_result.response_time` is exposed to C callers as seconds in a `double` for
matching and numeric comparisons. The JSON `time` field is serialized in
httpx-style duration text such as `742us`, `3.5ms`, or `1.2s`.

Setters that parse user expressions, such as `cihx_options_set_ports`,
`cihx_options_set_match_status_code`, and `cihx_options_set_match_response_time`,
return an error code and only replace existing configuration after successful
validation. CDN matching and filtering are available with
`cihx_options_add_match_cdn` and `cihx_options_add_filter_cdn`.

CDN detection combines response-header signatures with a conservative built-in
set of common CDN edge CIDR ranges. `host_ip` is populated from libcurl's
primary IP on normal requests and from the forced address when
`cihx_options_set_probe_all_ips` is enabled.
