#include "../httpxlib/ci_httpx.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
  fprintf(stderr,
          "Usage: %s [-j] [-u target] [-l file] [options]\n"
          "\n"
          "Input:\n"
          "  -u, --target VALUE              target URL or host\n"
          "  -l, --list FILE                 file containing targets\n"
          "      --path VALUE                comma-separated paths or path file\n"
          "  -p, --ports VALUE               httpx-style ports expression\n"
          "\n"
          "Output/probes:\n"
          "  -j, --json                      emit JSONL\n"
          "  -o, --output FILE               write output to file\n"
          "      --include-response-header   include normalized/raw response header\n"
          "      --include-response          include request, response header and body\n"
          "      --include-chain             include redirect chain\n"
          "      --body-preview N            body preview size\n"
          "      --tech-detect               detect technologies\n"
          "\n"
          "Matchers/filters/extractors:\n"
          "      --match-code VALUE          status matcher, e.g. 200,301-302\n"
          "      --filter-code VALUE         status filter\n"
          "      --match-length VALUE        content-length matcher\n"
          "      --filter-length VALUE       content-length filter\n"
          "      --match-line-count VALUE    line-count matcher\n"
          "      --filter-line-count VALUE   line-count filter\n"
          "      --match-word-count VALUE    word-count matcher\n"
          "      --filter-word-count VALUE   word-count filter\n"
          "      --match-string VALUE        body/header substring matcher\n"
          "      --filter-string VALUE       body/header substring filter\n"
          "      --match-regex VALUE         body/header regex matcher\n"
          "      --filter-regex VALUE        body/header regex filter\n"
          "      --match-cdn VALUE           CDN provider matcher\n"
          "      --filter-cdn VALUE          CDN provider filter\n"
          "      --match-response-time VALUE response-time matcher, e.g. '< 1'\n"
          "      --match-condition VALUE     DSL-style result condition\n"
          "      --filter-condition VALUE    DSL-style result filter condition\n"
          "      --extract-regex VALUE       extract matching response body text\n"
          "      --extract-preset VALUE      url, ipv4, mail\n"
          "\n"
          "Request config:\n"
          "  -H, --header VALUE              request header\n"
          "  -x, --method VALUE              method or 'all'\n"
          "      --body VALUE                request body\n"
          "      --proxy VALUE               HTTP/SOCKS proxy\n"
          "  -r, --resolvers VALUE           custom resolvers, comma-separated or file\n"
          "      --probe-all-ips             probe every resolved address for a host\n"
          "      --follow-redirects          follow redirects\n"
          "      --follow-host-redirects     follow same-host redirects\n"
          "      --max-redirects N           max redirects\n"
          "      --auto-referer              set referer during manual redirects\n"
          "      --random-agent              enable random User-Agent (default)\n"
          "      --no-random-agent           disable random User-Agent\n"
          "      --no-fallback               keep both HTTP and HTTPS results for host input\n"
          "      --no-fallback-scheme        only probe default scheme for host input\n"
          "      --default-scheme VALUE      http or https\n"
          "      --retries N                 retry failed transfers\n"
          "      --timeout N                 timeout seconds\n",
          argv0);
}

struct plain_ctx {
  FILE *fp;
  unsigned int display_flags;
};

static void plain_append_string(FILE *fp, const char *value)
{
  fprintf(fp, " [%s]", value && *value ? value : "-");
}

static void plain_append_long(FILE *fp, long value)
{
  fprintf(fp, " [%ld]", value);
}

static int print_plain(const cihx_result *result, void *userdata)
{
  struct plain_ctx *ctx = userdata;
  FILE *fp = ctx && ctx->fp ? ctx->fp : stdout;
  unsigned int flags = ctx ? ctx->display_flags : 0;

  fprintf(fp, "%s", result->url);
  if(flags & CIHX_PROBE_STATUS_CODE)
    plain_append_long(fp, result->status_code);
  if(flags & CIHX_PROBE_CONTENT_LENGTH)
    plain_append_long(fp, result->content_length);
  if(flags & CIHX_PROBE_CONTENT_TYPE)
    plain_append_string(fp, result->content_type);
  if(flags & CIHX_PROBE_LOCATION)
    plain_append_string(fp, result->location);
  if(flags & CIHX_PROBE_LINE_COUNT)
    plain_append_long(fp, result->lines);
  if(flags & CIHX_PROBE_WORD_COUNT)
    plain_append_long(fp, result->words);
  if(flags & CIHX_PROBE_TITLE)
    plain_append_string(fp, result->title);
  if(flags & CIHX_PROBE_BODY_PREVIEW)
    plain_append_string(fp, result->body_preview);
  if(flags & CIHX_PROBE_WEB_SERVER)
    plain_append_string(fp, result->webserver);
  if(flags & CIHX_PROBE_CDN)
    plain_append_string(fp, result->cdn_name);
  if(flags & CIHX_PROBE_TECH_DETECT)
    plain_append_string(fp, result->tech);
  fputc('\n', fp);
  return 0;
}

static unsigned int probe_flag_for_name(const char *name)
{
  if(!strcmp(name, "status-code"))
    return CIHX_PROBE_STATUS_CODE;
  if(!strcmp(name, "content-length"))
    return CIHX_PROBE_CONTENT_LENGTH;
  if(!strcmp(name, "content-type"))
    return CIHX_PROBE_CONTENT_TYPE;
  if(!strcmp(name, "location"))
    return CIHX_PROBE_LOCATION;
  if(!strcmp(name, "line-count"))
    return CIHX_PROBE_LINE_COUNT;
  if(!strcmp(name, "word-count"))
    return CIHX_PROBE_WORD_COUNT;
  if(!strcmp(name, "title"))
    return CIHX_PROBE_TITLE;
  if(!strcmp(name, "body-preview"))
    return CIHX_PROBE_BODY_PREVIEW;
  if(!strcmp(name, "server") || !strcmp(name, "web-server"))
    return CIHX_PROBE_WEB_SERVER;
  if(!strcmp(name, "cdn"))
    return CIHX_PROBE_CDN;
  return 0;
}

struct option_alias {
  const char *from;
  const char *to;
};

static const struct option_alias httpx_aliases[] = {
  {"-list", "--list"},
  {"-target", "--target"},
  {"-path", "--path"},
  {"-ports", "--ports"},
  {"-output", "--output"},
  {"-json", "--json"},
  {"-sc", "--status-code"},
  {"-status-code", "--status-code"},
  {"-cl", "--content-length"},
  {"-content-length", "--content-length"},
  {"-ct", "--content-type"},
  {"-content-type", "--content-type"},
  {"-location", "--location"},
  {"-lc", "--line-count"},
  {"-line-count", "--line-count"},
  {"-wc", "--word-count"},
  {"-word-count", "--word-count"},
  {"-title", "--title"},
  {"-bp", "--body-preview"},
  {"-body-preview", "--body-preview"},
  {"-server", "--server"},
  {"-web-server", "--web-server"},
  {"-td", "--tech-detect"},
  {"-tech-detect", "--tech-detect"},
  {"-cdn", "--cdn"},
  {"-irh", "--include-response-header"},
  {"-include-response-header", "--include-response-header"},
  {"-irr", "--include-response"},
  {"-include-response", "--include-response"},
  {"-include-chain", "--include-chain"},
  {"-mc", "--match-code"},
  {"-match-code", "--match-code"},
  {"-ml", "--match-length"},
  {"-match-length", "--match-length"},
  {"-mlc", "--match-line-count"},
  {"-match-line-count", "--match-line-count"},
  {"-mwc", "--match-word-count"},
  {"-match-word-count", "--match-word-count"},
  {"-ms", "--match-string"},
  {"-match-string", "--match-string"},
  {"-mr", "--match-regex"},
  {"-match-regex", "--match-regex"},
  {"-mcdn", "--match-cdn"},
  {"-match-cdn", "--match-cdn"},
  {"-fcdn", "--filter-cdn"},
  {"-filter-cdn", "--filter-cdn"},
  {"-mrt", "--match-response-time"},
  {"-match-response-time", "--match-response-time"},
  {"-mdc", "--match-condition"},
  {"-match-condition", "--match-condition"},
  {"-er", "--extract-regex"},
  {"-extract-regex", "--extract-regex"},
  {"-ep", "--extract-preset"},
  {"-extract-preset", "--extract-preset"},
  {"-fc", "--filter-code"},
  {"-filter-code", "--filter-code"},
  {"-fl", "--filter-length"},
  {"-filter-length", "--filter-length"},
  {"-flc", "--filter-line-count"},
  {"-filter-line-count", "--filter-line-count"},
  {"-fwc", "--filter-word-count"},
  {"-filter-word-count", "--filter-word-count"},
  {"-fs", "--filter-string"},
  {"-filter-string", "--filter-string"},
  {"-fe", "--filter-regex"},
  {"-filter-regex", "--filter-regex"},
  {"-frt", "--filter-response-time"},
  {"-filter-response-time", "--filter-response-time"},
  {"-fdc", "--filter-condition"},
  {"-filter-condition", "--filter-condition"},
  {"-pa", "--probe-all-ips"},
  {"-probe-all-ips", "--probe-all-ips"},
  {"-random-agent", "--random-agent"},
  {"-auto-referer", "--auto-referer"},
  {"-header", "--header"},
  {"-resolvers", "--resolvers"},
  {"-http-proxy", "--http-proxy"},
  {"-proxy", "--proxy"},
  {"-fr", "--follow-redirects"},
  {"-follow-redirects", "--follow-redirects"},
  {"-maxr", "--max-redirects"},
  {"-max-redirects", "--max-redirects"},
  {"-fhr", "--follow-host-redirects"},
  {"-follow-host-redirects", "--follow-host-redirects"},
  {"-body", "--body"},
  {"-nf", "--no-fallback"},
  {"-no-fallback", "--no-fallback"},
  {"-nfs", "--no-fallback-scheme"},
  {"-no-fallback-scheme", "--no-fallback-scheme"},
  {"-default-scheme", "--default-scheme"},
  {"-no-random-agent", "--no-random-agent"},
  {"-retries", "--retries"},
  {"-timeout", "--timeout"},
  {NULL, NULL}
};

static const char *canonical_arg(const char *arg)
{
  size_t i;
  for(i = 0; httpx_aliases[i].from; i++) {
    if(!strcmp(arg, httpx_aliases[i].from))
      return httpx_aliases[i].to;
  }
  return arg;
}

static char **canonicalize_argv(int argc, char **argv)
{
  char **out;
  int i;

  out = calloc((size_t)argc + 1, sizeof(*out));
  if(!out)
    return NULL;
  out[0] = argv[0];
  for(i = 1; i < argc; i++) {
    const char *mapped = canonical_arg(argv[i]);
    if((!strcmp(mapped, "--body-preview") ||
        !strcmp(mapped, "--body-preview-size")) &&
       i + 1 < argc && argv[i + 1][0] != '-') {
      out[i] = "--body-preview-size";
    }
    else {
      out[i] = (char *)mapped;
    }
  }
  return out;
}

static unsigned int preset_bit(const char *value)
{
  if(!strcmp(value, "url"))
    return CIHX_EXTRACT_PRESET_URL;
  if(!strcmp(value, "ipv4"))
    return CIHX_EXTRACT_PRESET_IPV4;
  if(!strcmp(value, "mail"))
    return CIHX_EXTRACT_PRESET_MAIL;
  return 0;
}

static int parse_long_option(const char *value, long min, long max, long *out)
{
  char *end = NULL;
  long parsed;

  if(!value || !*value || !out)
    return -1;
  errno = 0;
  parsed = strtol(value, &end, 10);
  if(errno || end == value)
    return -1;
  while(*end) {
    if(*end != ' ' && *end != '\t' && *end != '\r' && *end != '\n')
      return -1;
    end++;
  }
  if(parsed < min || parsed > max)
    return -1;
  *out = parsed;
  return 0;
}

int main(int argc, char **argv)
{
  cihx_options *opts;
  int c;
  int option_index = 0;
  bool json = false;
  FILE *output = NULL;
  const char *output_path = NULL;
  unsigned int presets = 0;
  unsigned int display_flags = 0;
  struct plain_ctx plain = {0};
  int rc;

  enum {
    OPT_PATH = 1000,
    OPT_PORTS,
    OPT_IRH,
    OPT_IRR,
    OPT_CHAIN,
    OPT_BP,
    OPT_TD,
    OPT_MC,
    OPT_FC,
    OPT_ML,
    OPT_FL,
    OPT_MLC,
    OPT_FLC,
    OPT_MWC,
    OPT_FWC,
    OPT_MS,
    OPT_FS,
    OPT_MR,
    OPT_FE,
    OPT_MCDN,
    OPT_FCDN,
    OPT_MRT,
    OPT_MDC,
    OPT_FRT,
    OPT_FDC,
    OPT_ER,
    OPT_EP,
    OPT_BODY,
    OPT_PROXY,
    OPT_PA,
    OPT_FR,
    OPT_FHR,
    OPT_MAXR,
    OPT_AUTO_REFERER,
    OPT_RANDOM_AGENT,
    OPT_NO_RANDOM_AGENT,
    OPT_NF,
    OPT_NFS,
    OPT_DEFAULT_SCHEME,
    OPT_RESOLVERS,
    OPT_RETRIES,
    OPT_TIMEOUT,
    OPT_PROBE_FIELD
  };

  static struct option long_options[] = {
    {"target", required_argument, NULL, 'u'},
    {"list", required_argument, NULL, 'l'},
    {"json", no_argument, NULL, 'j'},
    {"output", required_argument, NULL, 'o'},
    {"header", required_argument, NULL, 'H'},
    {"method", required_argument, NULL, 'x'},
    {"resolvers", required_argument, NULL, 'r'},
    {"path", required_argument, NULL, OPT_PATH},
    {"ports", required_argument, NULL, OPT_PORTS},
    {"include-response-header", no_argument, NULL, OPT_IRH},
    {"include-response", no_argument, NULL, OPT_IRR},
    {"include-chain", no_argument, NULL, OPT_CHAIN},
    {"body-preview", optional_argument, NULL, OPT_PROBE_FIELD},
    {"body-preview-size", required_argument, NULL, OPT_BP},
    {"status-code", no_argument, NULL, OPT_PROBE_FIELD},
    {"content-length", no_argument, NULL, OPT_PROBE_FIELD},
    {"content-type", no_argument, NULL, OPT_PROBE_FIELD},
    {"location", no_argument, NULL, OPT_PROBE_FIELD},
    {"line-count", no_argument, NULL, OPT_PROBE_FIELD},
    {"word-count", no_argument, NULL, OPT_PROBE_FIELD},
    {"title", no_argument, NULL, OPT_PROBE_FIELD},
    {"server", no_argument, NULL, OPT_PROBE_FIELD},
    {"web-server", no_argument, NULL, OPT_PROBE_FIELD},
    {"cdn", no_argument, NULL, OPT_PROBE_FIELD},
    {"tech-detect", no_argument, NULL, OPT_TD},
    {"match-code", required_argument, NULL, OPT_MC},
    {"filter-code", required_argument, NULL, OPT_FC},
    {"match-length", required_argument, NULL, OPT_ML},
    {"filter-length", required_argument, NULL, OPT_FL},
    {"match-line-count", required_argument, NULL, OPT_MLC},
    {"filter-line-count", required_argument, NULL, OPT_FLC},
    {"match-word-count", required_argument, NULL, OPT_MWC},
    {"filter-word-count", required_argument, NULL, OPT_FWC},
    {"match-string", required_argument, NULL, OPT_MS},
    {"filter-string", required_argument, NULL, OPT_FS},
    {"match-regex", required_argument, NULL, OPT_MR},
    {"filter-regex", required_argument, NULL, OPT_FE},
    {"match-cdn", required_argument, NULL, OPT_MCDN},
    {"filter-cdn", required_argument, NULL, OPT_FCDN},
    {"match-response-time", required_argument, NULL, OPT_MRT},
    {"match-condition", required_argument, NULL, OPT_MDC},
    {"filter-response-time", required_argument, NULL, OPT_FRT},
    {"filter-condition", required_argument, NULL, OPT_FDC},
    {"extract-regex", required_argument, NULL, OPT_ER},
    {"extract-preset", required_argument, NULL, OPT_EP},
    {"body", required_argument, NULL, OPT_BODY},
    {"proxy", required_argument, NULL, OPT_PROXY},
    {"http-proxy", required_argument, NULL, OPT_PROXY},
    {"probe-all-ips", no_argument, NULL, OPT_PA},
    {"follow-redirects", no_argument, NULL, OPT_FR},
    {"follow-host-redirects", no_argument, NULL, OPT_FHR},
    {"max-redirects", required_argument, NULL, OPT_MAXR},
    {"auto-referer", no_argument, NULL, OPT_AUTO_REFERER},
    {"random-agent", no_argument, NULL, OPT_RANDOM_AGENT},
    {"no-random-agent", no_argument, NULL, OPT_NO_RANDOM_AGENT},
    {"no-fallback", no_argument, NULL, OPT_NF},
    {"no-fallback-scheme", no_argument, NULL, OPT_NFS},
    {"default-scheme", required_argument, NULL, OPT_DEFAULT_SCHEME},
    {"retries", required_argument, NULL, OPT_RETRIES},
    {"timeout", required_argument, NULL, OPT_TIMEOUT},
    {0, 0, 0, 0}
  };

  opts = cihx_options_new();
  if(!opts) {
    fprintf(stderr, "failed to allocate options\n");
    return 2;
  }

  argv = canonicalize_argv(argc, argv);
  if(!argv) {
    fprintf(stderr, "failed to allocate argv\n");
    cihx_options_free(opts);
    return 2;
  }
  optind = 1;

  while((c = getopt_long(argc, argv, "u:l:jo:H:x:p:r:", long_options,
                         &option_index)) != -1) {
    switch(c) {
    case 'u':
      rc = cihx_options_add_target(opts, optarg);
      break;
    case 'l':
      rc = cihx_options_add_targets_file(opts, optarg);
      break;
    case 'j':
      json = true;
      rc = 0;
      break;
    case 'o':
      output_path = optarg;
      rc = 0;
      break;
    case 'H':
      rc = cihx_options_add_header(opts, optarg);
      break;
    case 'r':
      rc = cihx_options_add_resolver(opts, optarg);
      break;
    case 'x':
      rc = cihx_options_add_method(opts, optarg);
      break;
    case 'p':
      rc = cihx_options_set_ports(opts, optarg);
      break;
    case OPT_PATH:
      rc = cihx_options_add_path(opts, optarg);
      break;
    case OPT_PORTS:
      rc = cihx_options_set_ports(opts, optarg);
      break;
    case OPT_IRH:
      cihx_options_set_include_response_header(opts, true);
      rc = 0;
      break;
    case OPT_IRR:
      cihx_options_set_include_response(opts, true);
      rc = 0;
      break;
    case OPT_CHAIN:
      cihx_options_set_include_chain(opts, true);
      rc = 0;
      break;
    case OPT_BP:
      {
        long parsed;
        display_flags |= CIHX_PROBE_BODY_PREVIEW;
        rc = parse_long_option(optarg, 0, LONG_MAX, &parsed);
        if(!rc)
          rc = cihx_options_set_body_preview_size(opts, (size_t)parsed);
      }
      break;
    case OPT_PROBE_FIELD:
      display_flags |= probe_flag_for_name(long_options[option_index].name);
      if(!strcmp(long_options[option_index].name, "body-preview") && optarg) {
        long parsed;
        rc = parse_long_option(optarg, 0, LONG_MAX, &parsed);
        if(!rc)
          rc = cihx_options_set_body_preview_size(opts, (size_t)parsed);
      }
      else {
        rc = 0;
      }
      break;
    case OPT_TD:
      display_flags |= CIHX_PROBE_TECH_DETECT;
      cihx_options_set_tech_detect(opts, true);
      rc = 0;
      break;
    case OPT_MC:
      rc = cihx_options_set_match_status_code(opts, optarg);
      break;
    case OPT_FC:
      rc = cihx_options_set_filter_status_code(opts, optarg);
      break;
    case OPT_ML:
      rc = cihx_options_set_match_content_length(opts, optarg);
      break;
    case OPT_FL:
      rc = cihx_options_set_filter_content_length(opts, optarg);
      break;
    case OPT_MLC:
      rc = cihx_options_set_match_line_count(opts, optarg);
      break;
    case OPT_FLC:
      rc = cihx_options_set_filter_line_count(opts, optarg);
      break;
    case OPT_MWC:
      rc = cihx_options_set_match_word_count(opts, optarg);
      break;
    case OPT_FWC:
      rc = cihx_options_set_filter_word_count(opts, optarg);
      break;
    case OPT_MS:
      rc = cihx_options_add_match_string(opts, optarg);
      break;
    case OPT_FS:
      rc = cihx_options_add_filter_string(opts, optarg);
      break;
    case OPT_MR:
      rc = cihx_options_add_match_regex(opts, optarg);
      break;
    case OPT_FE:
      rc = cihx_options_add_filter_regex(opts, optarg);
      break;
    case OPT_MCDN:
      rc = cihx_options_add_match_cdn(opts, optarg);
      break;
    case OPT_FCDN:
      rc = cihx_options_add_filter_cdn(opts, optarg);
      break;
    case OPT_MRT:
      rc = cihx_options_set_match_response_time(opts, optarg);
      break;
    case OPT_MDC:
      rc = cihx_options_set_match_condition(opts, optarg);
      break;
    case OPT_FRT:
      rc = cihx_options_set_filter_response_time(opts, optarg);
      break;
    case OPT_FDC:
      rc = cihx_options_set_filter_condition(opts, optarg);
      break;
    case OPT_ER:
      rc = cihx_options_add_extract_regex(opts, optarg);
      break;
    case OPT_EP:
      {
        unsigned int bit = preset_bit(optarg);
        if(!bit)
          rc = -1;
        else {
          presets |= bit;
          rc = 0;
        }
      }
      break;
    case OPT_BODY:
      cihx_options_set_body(opts, optarg);
      rc = 0;
      break;
    case OPT_PROXY:
      cihx_options_set_proxy(opts, optarg);
      rc = 0;
      break;
    case OPT_PA:
      cihx_options_set_probe_all_ips(opts, true);
      rc = 0;
      break;
    case OPT_FR:
      cihx_options_set_follow_redirects(opts, true);
      rc = 0;
      break;
    case OPT_FHR:
      cihx_options_set_follow_host_redirects(opts, true);
      rc = 0;
      break;
    case OPT_MAXR:
      {
        long parsed;
        rc = parse_long_option(optarg, 0, LONG_MAX, &parsed);
        if(!rc)
          rc = cihx_options_set_max_redirects(opts, parsed);
      }
      break;
    case OPT_AUTO_REFERER:
      cihx_options_set_auto_referer(opts, true);
      rc = 0;
      break;
    case OPT_RANDOM_AGENT:
      cihx_options_set_random_agent(opts, true);
      rc = 0;
      break;
    case OPT_NO_RANDOM_AGENT:
      cihx_options_set_random_agent(opts, false);
      rc = 0;
      break;
    case OPT_NF:
      cihx_options_set_no_fallback(opts, true);
      rc = 0;
      break;
    case OPT_NFS:
      cihx_options_set_no_fallback_scheme(opts, true);
      rc = 0;
      break;
    case OPT_DEFAULT_SCHEME:
      rc = cihx_options_set_default_scheme(opts, optarg);
      break;
    case OPT_RESOLVERS:
      rc = cihx_options_add_resolver(opts, optarg);
      break;
    case OPT_RETRIES:
      {
        long parsed;
        rc = parse_long_option(optarg, 0, LONG_MAX, &parsed);
        if(!rc)
          rc = cihx_options_set_retries(opts, parsed);
      }
      break;
    case OPT_TIMEOUT:
      {
        long parsed;
        rc = parse_long_option(optarg, 1, LONG_MAX, &parsed);
        if(!rc)
          rc = cihx_options_set_timeout(opts, parsed);
      }
      break;
    default:
      usage(argv[0]);
      cihx_options_free(opts);
      free(argv);
      return 2;
    }
    if(rc) {
      fprintf(stderr, "invalid option value: %s\n", cihx_strerror(rc));
      cihx_options_free(opts);
      free(argv);
      return 2;
    }
  }

  while(optind < argc) {
    rc = cihx_options_add_target(opts, argv[optind++]);
    if(rc) {
      fprintf(stderr, "invalid target: %s\n", cihx_strerror(rc));
      cihx_options_free(opts);
      free(argv);
      return 2;
    }
  }

  if(presets)
    cihx_options_set_extract_presets(opts, presets);
  if(json)
    cihx_options_set_tech_detect(opts, true);
  if(output_path) {
    output = fopen(output_path, "w");
    if(!output) {
      perror(output_path);
      cihx_options_free(opts);
      free(argv);
      return 2;
    }
  }
  if(json)
    cihx_options_set_json_output(opts, output ? output : stdout);
  plain.fp = output ? output : stdout;
  plain.display_flags = display_flags;
  rc = cihx_run(opts, json ? NULL : print_plain, &plain);
  if(rc)
    fprintf(stderr, "cihx_run failed: %s\n", cihx_strerror(rc));
  if(output)
    fclose(output);
  cihx_options_free(opts);
  free(argv);
  return rc ? 1 : 0;
}
