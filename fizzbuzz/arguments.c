#include <argp.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>

#include "arguments.h"


static char args_doc[] = "AMOUNT";

static char doc[] =
	"AMOUNT	the max number for our fizzbuzz\n";

enum fix_args {
	FIX_ARG_MAX = 0,
	FIX_ARG_CNT
};

static struct argp_option options[] = {
	{ 0 }
};

static error_t parse_opt(int key, char * arg, struct argp_state * state);

static struct argp argp = {
	options,
	parse_opt,
	args_doc,
	doc,
	0,
	0,
	0
};

static error_t parse_opt(int key, char * arg, struct argp_state * state)
{
	char *endptr;
	long tmp;
	struct arguments *args = state->input;

	switch (key) {
	case ARGP_KEY_ARG:
		switch(state->arg_num) {
		case FIX_ARG_MAX:
			tmp = strtol(arg, &endptr, 10);
			if (*endptr || endptr == arg) {
				fprintf(stderr, "Failed to parse argument\n");
				return -1;
			}
			args->max = tmp;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int parse_args(struct arguments * args, int argc, char ** argv)
{
	if (argc <= FIX_ARG_CNT)
		return -1;

	memset(args, 0, sizeof(*args));
	if (argp_parse(&argp, argc, argv, 0, 0, args))
		return -1;

	return 0;
}
