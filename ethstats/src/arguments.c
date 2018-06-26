#include <argp.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>

#include "arguments.h"


static char args_doc[] = "NUM";

static char doc[] =
	"ethstats: Analyze and count raw Ethernet frames\n"
	"-i	   interface from which frames should be read\n"
	"NUM	   number of frames to read before printing summary\n";

enum fix_args {
	FIX_ARG_NUM = 0,
	FIX_ARG_CNT
};

static struct argp_option options[] = {
	{
		"interface",
		'i',
		"interface",
		0,
		0,
		0
	},
	{ 0, 0, 0, 0, 0, 0 }
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
	struct arguments * args = state->input;
	char * ptr;

	switch (key) {
	case ARGP_KEY_ARG:
		switch(state->arg_num) {
		case FIX_ARG_NUM:
			args->frames = (int) strtol(arg, &ptr, 10);
			if(*ptr)
				return EINVAL;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'i':
		args->interface = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int parse_args(struct arguments * args, int argc, char ** argv)
{
	memset(args, 0, sizeof(*args));
	args->interface = "eth0";
	args->frames = 10;
	if(argp_parse(&argp, argc, argv, 0, 0, args))
		return -1;

	return 0;
}
