#define address_translation_c
#include "address_translation.h"
#include "ip6.h"
#include "scan.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

char *g_address_translation_rules_file;
static tr_ruleset rules;

static void panic(const char *x) {
	fprintf(stderr, x);
	exit(222);
}

void unload_translation_rules(void) {
	if (rules.n != 0) {
		free(rules.entry);
		rules.entry = NULL;
		rules.n = 0;
	}
}

#ifdef _DEBUG_TRANSLATION
void print_address(ot_ip6 a) {
#ifdef WANT_V6
	int i;
	for (i=0; i<8; ++i) {
		fprintf(stderr, "%s%02x%02x", i>0?":":"", 255&(int)a[i<<1], 255&(int)a[(i<<1)+1]);
	}
#else
	fprintf(stderr, "%u.%u.%u.%u", 255&(int)a[12], 255&(int)a[13], 255&(int)a[14], 255&(int)a[15]);
#endif
}
void print_address2(uint8_t *a) {
#ifdef WANT_V6
	int i;
	for (i=0; i<8; ++i) {
		fprintf(stderr, "%s%02x%02x", i>0?":":"", 255&(int)a[i<<1], 255&(int)a[(i<<1)+1]);
	}
#else
	fprintf(stderr, "%u.%u.%u.%u", 255&(int)a[0], 255&(int)a[1], 255&(int)a[2], 255&(int)a[3]);
#endif
}

void print_rule(tr_rule *r) {
	fprintf(stderr, "{ for ");
	print_address(r->for_whom.address);
	if (r->stopper) {
		fprintf(stderr, "/%d nothing more }\n", r->for_whom.bits);
	}
	else {
		fprintf(stderr, "/%d translate ", r->for_whom.bits);
		print_address(r->from.address);
		fprintf(stderr, "/%d to ", r->from.bits);
		print_address(r->to);
		fprintf(stderr, " }\n");
	}
}
#endif

void load_translation_rules(void) {
	unload_translation_rules();
	FILE *fh = fopen(g_address_translation_rules_file, "r");
	if (fh == NULL) panic("could not open translation rules file");
	char inbuf[512];
	size_t n = 8;
	rules.entry = malloc(sizeof(tr_rule) * n);
	if (rules.entry == NULL) panic("error allocating 8 translation rule entries");
	rules.n = 0;


	while (fgets(inbuf, sizeof(inbuf), fh)) {
		char *p = inbuf;
		if (rules.n == n) {
			n <<= 1;
			rules.entry = realloc(rules.entry, sizeof(tr_rule)*n);
			if (rules.entry == NULL) panic("error increasing the number of translation rule entries");
		}

		// lines should contain either comments:
		// # ...
		// or specifications:
		// "for" CIDR "translate" CIDR "to" IP
		// where the first CIDR is matched against the peer sending the announce request
		// the second CIDR is matched against the peers of the torrent of the announce request
		// and the IP is what the second CIDR is exchanged for

		if (strstr(p, "#") == p) continue; // comments
		if ((p = strstr(p, "for")) == NULL)                      panic("error reading ruleset keyword \"for\"\n");
		p += 3; while (isspace(*(++p)));
		if (!scan_ip6(p, rules.entry[rules.n].for_whom.address)) panic("error reading ruleset \"for_whom\" address\n");
		if ((p = strchr(p, '/')) == NULL)                        panic("error reading ruleset \"for_whom\" slash delimiter\n");
		p += 1;
		if (!scan_int(p, &rules.entry[rules.n].for_whom.bits))   panic("error reading ruleset \"for_whom\" bits\n");
		if (strstr(p, "nothing more") != NULL) {
			rules.entry[rules.n].stopper = 1;
		}
		else {
			rules.entry[rules.n].stopper = 0;
			if ((p = strstr(p, "translate")) == NULL)                panic("error reading ruleset keyword \"translate\"\n");
			p += 9; while (isspace(*(++p)));
			if (!scan_ip6(p, rules.entry[rules.n].from.address))     panic("error reading ruleset \"from\" address\n");
			if ((p = strchr(p, '/')) == NULL)                        panic("error reading ruleset \"from\" slash delimiter\n");
			p += 1;
			if (!scan_int(p, &rules.entry[rules.n].from.bits))       panic("error reading ruleset \"from\" bits\n");
			if ((p = strstr(p, "to")) == NULL)                       panic("error reading ruleset keyword \"to\"\n");
			p += 2; while (isspace(*(++p)));
			if (!scan_ip6(p, rules.entry[rules.n].to))               panic("error reading ruleset \"to\" address\n");
		}
#ifdef _DEBUG_TRANSLATION
		print_rule(&rules.entry[rules.n]);
#endif
		++rules.n;

	}
	rules.entry = realloc(rules.entry, sizeof(tr_rule) * rules.n);
#ifdef _DEBUG_TRANSLATION
	fprintf(stderr, "loaded %zu rules\n", rules.n);
#endif
}
int match_address(uint8_t *address, ot_net *net) {
	int bits = net->bits;
	size_t i;
	for (i=0; i<RULES_IP_LENGTH; ++i) {
		if (bits == 0) {
			return 1;
		}
		//uint8_t a = address[i];
		//uint8_t n = net->address[i+RULES_IP_OFFSET];
		uint8_t m = (uint8_t)(bits>=8 ? 255 : ~((1UL<<bits)-1));
/*
		fprintf(stderr,
			"byte %zu: a:%02x n:%02x m:%02x a&m:%02x n&m%02x (a&m)^(n&m):%02x (a^n)&m:%02x\n",
			i, a, n, m, a&m, n&m, (a&m)^(n&m), (a^n)&m);
*/

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
			if (rules.entry[i].stopper) {
#ifdef _DEBUG_TRANSLATION
				fprintf(stderr, "RULE MATCH\n");
				fprintf(stderr, "request from ");
				print_address2((char *)requester->data);
				fprintf(stderr, ", and peer is ");
				print_address2(peer);
				fprintf(stderr, " matches ");
				print_rule(&rules.entry[i]);
				fprintf(stderr, "\n");
#endif
				return;
			}
			else if (match_address((uint8_t *)peer, &rules.entry[i].from)) {
#ifdef _DEBUG_TRANSLATION
				fprintf(stderr, "RULE MATCH\n");
				fprintf(stderr, "request from ");
				print_address2((char *)requester->data);
				fprintf(stderr, ", and peer is ");
				print_address2(peer);
				fprintf(stderr, " matches ");
				print_rule(&rules.entry[i]);
				fprintf(stderr, "\n");
#endif
				OT_SETIP(peer, &rules.entry[i].to);
				return;
			}
		}
	}
}
#undef address_translation_c
