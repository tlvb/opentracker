#ifndef address_translation_h
#define address_translation_h
#include "trackerlogic.h"

#ifdef WANT_V6
#	define RULES_IP_LENGTH 16
#	define RULES_IP_OFFSET 0
#else
#	define RULES_IP_LENGTH 4
#	define RULES_IP_OFFSET 12
#endif

typedef struct {
	ot_net for_whom;
	uint8_t stopper;
	ot_net from;
	ot_ip6 to;
} tr_rule;

typedef struct {
	size_t n;
	tr_rule *entry;
} tr_ruleset;

#ifndef address_translation_c
extern char *g_address_translation_rules_file;
#endif

void load_translation_rules(void);
void unload_translation_rules(void);
void translate(char *peer, ot_peer *requester);

#endif
