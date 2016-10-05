// vim: et:ts=2:sw=2
#define address_translation_c
#include "address_translation.h"
#include "ip6.h"
#include "scan.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
char *g_address_translation_rules_file;
static tr_ruleset rules;

static void ruleset_error(const char *msg, const char *moremsg) {
  fprintf(stderr, "Ruleset loading error:\n\t%s\n\t\"%s\"\n\tAn empty ruleset will be used.\n", msg, moremsg);
  unload_translation_rules();
}

void unload_translation_rules(void) {
  if (rules.n != 0) {
    free(rules.entry);
    rules.entry = NULL;
    rules.n = 0;
  }
}

void load_translation_rules(void) {
  unload_translation_rules();
  FILE *fh = fopen(g_address_translation_rules_file, "r");
  if (fh == NULL)                                            { ruleset_error("Opening translation rules file failed.", strerror(errno)); return; }
  char inbuf[512];
  size_t n = 128;
  rules.entry = malloc(sizeof(tr_rule) * n);
  if (rules.entry == NULL)                                   { ruleset_error("Allocating memory for translation rule entries failed.", strerror(errno)); return; }

  while (fgets(inbuf, sizeof(inbuf), fh)) {
    char *p = inbuf;
    if (rules.n == n) {
      n <<= 1;
      rules.entry = realloc(rules.entry, sizeof(tr_rule)*n);
      if (rules.entry == NULL)                               { ruleset_error("Allocating more memory for translation rule entries failed.", strerror(errno)); return; }
    }

    int bits = 0;
    if (p[0] == '\0' || isspace(p[0]) || p[0] == '#') continue; // comments and empty lines
    if ((p = strstr(p, "for")) == NULL)                      { ruleset_error("Expected keyword \"for\"", inbuf); return; }
    p += 3; while (isspace(*(++p)));
    if (!scan_ip6(p, rules.entry[rules.n].for_whom.address)) { ruleset_error("Expected IP/BITS after \"for\": malformed IP", inbuf); return; }
    if ((p = strchr(p, '/')) == NULL)                        { ruleset_error("Expected IP/BITS after \"for\": malformed \"/\"", inbuf); return; }
    p += 1;
    if (!scan_int(p, &bits))                                 { ruleset_error("Expected IP/BITS after \"for\": malformed BITS", inbuf); return; }
    if (bits < 0 || bits > RULES_IP_BIT_COUNT)               { ruleset_error("Expected IP/BITS after \"for\": invalid amount of BITS", inbuf); return; }
    rules.entry[rules.n].for_whom.bits = bits;
    if (strstr(p, "nothing more") != NULL) {
      rules.entry[rules.n].stopper = 1;
    }
    else {
      rules.entry[rules.n].stopper = 0;
      if ((p = strstr(p, "translate")) == NULL)              { ruleset_error("Expected key sequences \"translate\" or \"nothing more\"", inbuf); return; }
      p += 9; while (isspace(*(++p)));
      if (!scan_ip6(p, rules.entry[rules.n].from.address))   { ruleset_error("Expected IP/BITS after \"translate\": malformed IP", inbuf); return; }
      if ((p = strchr(p, '/')) == NULL)                      { ruleset_error("Expected IP/BITS after \"translate\": malformed \"/\"", inbuf); return; }
      p += 1;
      if (!scan_int(p, &bits))                               { ruleset_error("Expected IP/BITS after \"translate\": malformed BITS", inbuf); return; }
      if (bits < 0 || bits > RULES_IP_BIT_COUNT)             { ruleset_error("Expected IP/BITS after \"translate\": invalid amount of BITS", inbuf); return; }
      rules.entry[rules.n].from.bits = bits;
      if ((p = strstr(p, "to")) == NULL)                     { ruleset_error("Expected keyword \"to\"", inbuf); return; }
      p += 2; while (isspace(*(++p)));
      if (!scan_ip6(p, rules.entry[rules.n].to))             { ruleset_error("Expected IP after \"to\"", inbuf); return; }
    }
    ++rules.n;
  }
  rules.entry = realloc(rules.entry, sizeof(tr_rule) * rules.n);
#ifdef _DEBUG
  fprintf(stderr, "loaded %zu address translation rules\n", rules.n);
#endif
}

int match_address(uint8_t *address, ot_net *net) {
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

void translate(char *peer, ot_peer *requester) {
  size_t i;
  for (i=0; i<rules.n; ++i) {
    if (match_address(requester->data, &rules.entry[i].for_whom)) {
      if (rules.entry[i].stopper) return;
      else if (match_address((uint8_t *)peer, &rules.entry[i].from)) {
        OT_SETIP(peer, &rules.entry[i].to);
        return;
      }
    }
  }
}
#undef address_translation_c
