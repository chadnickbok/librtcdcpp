/**
 * Simple demo client using libwebsocket and librtcdcpp.
 */

#include <lws_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>

#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>

#include <libwebsockets.h>

static int deny_deflate, deny_mux, longlived, mirror_lifetime;
static struct lws *wsi_testrtc;
static volatile int force_exit;
static unsigned int opts;

enum demo_protocols {
  PROTOCOL_TESTRTC,

  /* always last */
  DEMO_PROTOCOL_COUNT
};


static int
callback_testrtcdc(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
  switch (reason) {
  case LWS_CALLBACK_CLIENT_ESTABLISHED:
    lwsl_info("dumb: LWS_CALLBACK_CLIENT_ESTABLISHED\n");
    break;

  case LWS_CALLBACK_CLOSED:
    lwsl_notice("dumb: LWS_CALLBACK_CLOSED\n");
    wsi_testrtc = NULL;
    break;

  case LWS_CALLBACK_CLIENT_RECEIVE:
    ((char *)in)[len] = '\0';
    lwsl_info("rx %d '%s'\n", (int)len, (char *)in);
    break;

  /* because we are protocols[0] ... */

  case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
    lwsl_err("CLIENT_CONNECTION_ERROR: testrtc: %s %p\n", in);
    break;

  case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
    if ((strcmp(in, "deflate-stream") == 0) && deny_deflate) {
      lwsl_notice("denied deflate-stream extension\n");
      return 1;
    }
    if ((strcmp(in, "x-webkit-deflate-frame") == 0)) {
      return 1;
    }
    if ((strcmp(in, "deflate-frame") == 0)) {
      return 1;
    }
    break;

  case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
  {
    char buffer[1024 + LWS_PRE];
    char *px = buffer + LWS_PRE;
    int lenx = sizeof(buffer) - LWS_PRE;

    lwsl_notice("LWS_CALLBACK_RECEIVE_CLIENT_HTTP\n");

    /*
     * Often you need to flow control this by something
     * else being writable.  In that case call the api
     * to get a callback when writable here, and do the
     * pending client read in the writeable callback of
     * the output.
     * What does that even mean? Who wrote this shit?
     */
    if (lws_http_client_read(wsi, &px, &lenx) < 0) {
      return -1;
    }
    while (lenx--) {
      putchar(*px++);
    }
  }
  break;

  case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
    wsi_testrtc = NULL;
    force_exit = 1;
    break;

  default:
    break;
  }

  return 0;
}


/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
  {
    "testrtc-protocol,fake-nonexistant-protocol",
    callback_testrtcdc,
    0,
    2048,
  },
  { NULL, NULL, 0, 0 } /* end */
};

static const struct lws_extension exts[] = {
  {
    "permessage-deflate",
    lws_extension_callback_pm_deflate,
    "permessage-deflate; client_max_window_bits"
  },
  {
    "deflate-frame",
    lws_extension_callback_pm_deflate,
    "deflate_frame"
  },
  { NULL, NULL, NULL /* terminator */ }
};

void sighandler(int sig)
{
  force_exit = 1;
}

static struct option options[] = {
  { "help",       no_argument,        NULL, 'h' },
  { "debug",      required_argument,  NULL, 'd' },
  { "port",       required_argument,  NULL, 'p' },
  { "version",    required_argument,  NULL, 'v' },
  { "undeflated", no_argument,        NULL, 'u' },
  { "nomux",      no_argument,        NULL, 'n' },
  { "longlived",  no_argument,        NULL, 'l' },
  { NULL, 0, 0, 0 }
};

static int ratelimit_connects(unsigned int *last, unsigned int secs)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  if (tv.tv_sec - (*last) < secs) {
    return 0;
  }

  *last = tv.tv_sec;

  return 1;
}

void usage() {
  fprintf(stderr, "Usage: libwebsockets-test-client "
        "<server address> [--port=<p>] [-v <ver>] [-d <log bitfield>] [-l]\n");
}

int main(int argc, char **argv)
{
  int n = 0, ret = 0, port = 7681, ietf_version = -1;
  unsigned int rl_testrtc = 0, do_ws = 1;
  struct lws_context_creation_info info;
  struct lws_client_connect_info i;
  struct lws_context *context;
  const char *prot, *p;
  char path[300];

  memset(&info, 0, sizeof info);

  lwsl_notice("librtcdcpp test client\n");

  if (argc < 2) {
    usage();
    return 1;
  }

  while (n >= 0) {
    n = getopt_long(argc, argv, "Snuv:hsp:d:lC:K:A:", options, NULL);
    if (n < 0) {
      continue;
    }

    switch (n) {
    case 'd':
      lws_set_log_level(atoi(optarg), NULL);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'l':
      longlived = 1;
      break;
    case 'v':
      ietf_version = atoi(optarg);
      break;
    case 'u':
      deny_deflate = 1;
      break;
    case 'n':
      deny_mux = 1;
      break;
    case 'h':
      usage();
      return 1;
      break;
    }
  }

  if (optind >= argc) {
    usage();
    return 1;
  }

  signal(SIGINT, sighandler);

  memset(&i, 0, sizeof(i));

  i.port = port;
  if (lws_parse_uri(argv[optind], &prot, &i.address, &i.port, &p)) {
    usage();
    return 1;
  }

  /* add back the leading / on path */
  path[0] = '/';
  strncpy(path + 1, p, sizeof(path) - 2);
  path[sizeof(path) - 1] = '\0';
  i.path = path;

  /*
   * create the websockets context.  This tracks open connections and
   * knows how to route any traffic and which protocol version to use,
   * and if each connection is client or server side.
   *
   * For this client-only demo, we tell it to not listen on any port.
   */

   lwsl_info("create context\n");
  info.port = CONTEXT_PORT_NO_LISTEN;
  info.protocols = protocols;
  info.gid = -1;
  info.uid = -1;

  context = lws_create_context(&info);
  if (context == NULL) {
    fprintf(stderr, "Creating libwebsocket context failed\n");
    return 1;
  }

  i.context = context;
  i.ssl_connection = 0;
  i.host = i.address;
  i.origin = i.address;
  i.ietf_version_or_minus_one = ietf_version;
  i.client_exts = exts;

  lwsl_notice("using %s mode (ws)\n", prot);

  /*
   * sit there servicing the websocket context to handle incoming packets
   *
   * nothing happens until the client websocket connection is
   * asynchronously established... calling lws_client_connect() only
   * instantiates the connection logically, lws_service() progresses it
   * asynchronously.
   */

	while (!force_exit) {

    if (!wsi_testrtc && ratelimit_connects(&rl_testrtc, 2u)) {
      lwsl_notice("dumb: connecting\n");
      i.protocol = protocols[PROTOCOL_TESTRTC].name;
      i.pwsi = &wsi_testrtc;
      lws_client_connect_via_info(&i);
    }

    lws_service(context, 500);
  }

  lwsl_err("Exiting\n");
  lws_context_destroy(context);

  return ret;
}
