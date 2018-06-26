#include <stdio.h>
#include "arguments.h"


void assignment1(long max)
{
	long i;
	for(i = 1; i <= max; i++) {
		if(i % 15 == 0) {
			printf("FizzBuzz\n");
		}
		else if(i % 3 == 0) {
			printf("Fizz\n");
		}
		else if(i % 5 == 0) {
			printf("Buzz\n");
		}
		else {
			printf("%ld\n", i);
		}
	}

/*====================================TODO===================================*/

/*===========================================================================*/
}

int main(int argc, char ** argv)
{
	struct arguments args;

	if (parse_args(&args, argc, argv) < 0) {
		fprintf(stderr, "Failed to parse arguments, call with "
			"--help for more information\n");
		return -1;
	}

	assignment1(args.max);

	return 0;
}
