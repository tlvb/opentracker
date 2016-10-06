// vim: et:ts=2:sw=2
#ifdef WANT_TRANSLATION
#define address_translation_c
#include "address_translation.h"
#include "ip6.h"
#include "scan.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
       char *g_address_translation_rules_file;
static tr_ruleset g_translation_rules;
static pthread_mutex_t g_translation_rules_mutex;

static void free_translation_rules(void) {
  if (g_translation_rules.n != 0) {
    free(g_translation_rules.entry);
    g_translation_rules.entry = NULL;
    g_translation_rules.n = 0;
  }
}

static void ruleset_error(const char *msg, const char *moremsg) {
  fprintf(stderr, "\nRuleset loading error:\n\t%s\n\t\"%s\"\n\tAn empty ruleset will be used.\n", msg, moremsg);
  free_translation_rules();
  pthread_mutex_unlock(&g_translation_rules_mutex);
}


static void reload_translation_rules(void) {
  // note that on error, mutex unlocking is handled
  // by ruleset_error()
  pthread_mutex_lock(&g_translation_rules_mutex);
  free_translation_rules();
  FILE *fh = fopen(g_address_translation_rules_file, "r");
  if (fh == NULL)                                                                       { ruleset_error("Opening translation rules file failed.", strerror(errno)); return; }
  char inbuf[512];
  size_t n = 128;
  g_translation_rules.entry = malloc(sizeof(tr_rule) * n);
  if (g_translation_rules.entry == NULL)                                                { ruleset_error("Allocating memory for translation rule entries failed.", strerror(errno)); return; }

  while (fgets(inbuf, sizeof(inbuf), fh)) {
    char *p = inbuf;
    if (g_translation_rules.n == n) {
      n <<= 1;
      g_translation_rules.entry = realloc(g_translation_rules.entry, sizeof(tr_rule)*n);
      if (g_translation_rules.entry == NULL)                                            { ruleset_error("Allocating more memory for translation rule entries failed.", strerror(errno)); return; }
    }

    int bits = 0;
    if (p[0] == '\0' || isspace(p[0]) || p[0] == '#') continue; // comments and empty lines
    if ((p = strstr(p, "for")) == NULL)                                                  { ruleset_error("Expected keyword \"for\"", inbuf); return; }
    p += 3; while (isspace(*(++p)));
    if (!scan_ip6(p, g_translation_rules.entry[g_translation_rules.n].for_whom.address)) { ruleset_error("Expected IP/BITS after \"for\": malformed IP", inbuf); return; }
    if ((p = strchr(p, '/')) == NULL)                                                    { ruleset_error("Expected IP/BITS after \"for\": malformed \"/\"", inbuf); return; }
    p += 1;
    if (!scan_int(p, &bits))                                                             { ruleset_error("Expected IP/BITS after \"for\": malformed BITS", inbuf); return; }
    if (bits < 0 || bits > RULES_IP_BIT_COUNT)                                           { ruleset_error("Expected IP/BITS after \"for\": invalid amount of BITS", inbuf); return; }
    g_translation_rules.entry[g_translation_rules.n].for_whom.bits = bits;
    if (strstr(p, "no further action") != NULL) {
      g_translation_rules.entry[g_translation_rules.n].stopper = 1;
    }
    else {
      g_translation_rules.entry[g_translation_rules.n].stopper = 0;
      if ((p = strstr(p, "translate")) == NULL)                                          { ruleset_error("Expected key sequences \"translate\" or \"no further action\"", inbuf); return; }
      p += 9; while (isspace(*(++p)));
      if (!scan_ip6(p, g_translation_rules.entry[g_translation_rules.n].from.address))   { ruleset_error("Expected IP/BITS after \"translate\": malformed IP", inbuf); return; }
      if ((p = strchr(p, '/')) == NULL)                                                  { ruleset_error("Expected IP/BITS after \"translate\": malformed \"/\"", inbuf); return; }
      p += 1;
      if (!scan_int(p, &bits))                                                           { ruleset_error("Expected IP/BITS after \"translate\": malformed BITS", inbuf); return; }
      if (bits < 0 || bits > RULES_IP_BIT_COUNT)                                         { ruleset_error("Expected IP/BITS after \"translate\": invalid amount of BITS", inbuf); return; }
      g_translation_rules.entry[g_translation_rules.n].from.bits = bits;
      if ((p = strstr(p, "to")) == NULL)                                                 { ruleset_error("Expected keyword \"to\"", inbuf); return; }
      p += 2; while (isspace(*(++p)));
      if (!scan_ip6(p, g_translation_rules.entry[g_translation_rules.n].to))             { ruleset_error("Expected IP after \"to\"", inbuf); return; }
    }
    ++g_translation_rules.n;
  }
  g_translation_rules.entry = realloc(g_translation_rules.entry, sizeof(tr_rule) * g_translation_rules.n);
#ifdef _DEBUG
  fprintf(stderr, "\nloaded %zu address translation rules\n", g_translation_rules.n);
#endif
  pthread_mutex_unlock(&g_translation_rules_mutex);
}

// more or less verbatim from ot_accesslist.c
static void *translation_rules_worker(void *args) {
  int sig;
  sigset_t signal_mask;
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGUSR1);
  (void)args;
  for (;;) {
    reload_translation_rules();
    while (sigwait(&signal_mask, &sig) != 0 && sig != SIGUSR1);
  }
  return NULL;
}

static int match_address(uint8_t *address, ot_net *net) {
  int bits = net->bits;
  size_t i;
  for (i=0; i<RULES_IP_LENGTH; ++i) {
    if (bits == 0) {
      return 1;
    }
    uint8_t m = (uint8_t)(bits>=8 ? 255 : ~((1UL<<bits)-1));
    if (((address[i]^net->address[i+RULES_IP_OFFSET]) & m) != 0) {
      return 0;
    }
    bits -= 8;
  }
  return 1;
}

static pthread_t thread_id;
void translation_rules_init(void) {
  pthread_mutex_init(&g_translation_rules_mutex, NULL);
  pthread_create(&thread_id, NULL, translation_rules_worker, NULL);
}

void translation_rules_deinit(void) {
  pthread_cancel(thread_id);
  pthread_mutex_destroy(&g_translation_rules_mutex);
  free_translation_rules();
}

void translate(char *peer, ot_peer *requester) {
  size_t i;
  pthread_mutex_lock(&g_translation_rules_mutex);
  for (i=0; i<g_translation_rules.n; ++i) {
    if (match_address(requester->data, &g_translation_rules.entry[i].for_whom)) {
      if (g_translation_rules.entry[i].stopper) goto done;
      else if (match_address((uint8_t *)peer, &g_translation_rules.entry[i].from)) {
        OT_SETIP(peer, &g_translation_rules.entry[i].to);
        goto done;
      }
    }
  }
  done:
  pthread_mutex_unlock(&g_translation_rules_mutex);
}
#undef address_translation_c
#endif
