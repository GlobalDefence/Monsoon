//
//  main.cpp
//  brainfuck
//
//  Created by XuRuomeng on 14-2-3.
//  Copyright (c) 2014年 BlueCocoa. All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#	define isatty _isatty
#endif

#include "brainfuck.h"

void print_usage(void);
int run_file(FILE *file);
int run_string(char *code);
void run_interactive_console(void);

/*
 * Prints the usage message of this program.
 */
void print_usage() {
	fprintf(stderr, "usage: brainfuck [-eih] file...\n");
	fprintf(stderr,	"\t-e  run code directly\n");
	fprintf(stderr,	"\t-h  show a help message\n");
}

/*
 * Runs the given brainfuck file.
 *
 * @param file The brainfuck file to run.
 * @return EXIT_SUCCESS if no errors are encountered, otherwise EXIT_FAILURE.
 */
int run_file(FILE *file) {
	BrainfuckState *state = brainfuck_state();
	BrainfuckExecutionContext *context = brainfuck_context(BRAINFUCK_TAPE_SIZE);
	if (file == NULL) {
		brainfuck_destroy_context(context);
		brainfuck_destroy_state(state);
		return EXIT_FAILURE;
	}
	brainfuck_add(state, brainfuck_parse_stream(file));
	brainfuck_execute(state->root, context);
	brainfuck_destroy_context(context);
	brainfuck_destroy_state(state);
	fclose(file);
	return EXIT_SUCCESS;
}

/*
 * Runs the given brainfuck string.
 *
 * @param code The brainfuck string to run.
 * @return EXIT_SUCCESS if no errors are encountered, otherwise EXIT_FAILURE.
 */
int run_string(char *code) {
	BrainfuckState *state = brainfuck_state();
	BrainfuckExecutionContext *context = brainfuck_context(BRAINFUCK_TAPE_SIZE);
	BrainfuckInstruction *instruction = brainfuck_parse_string(code);
 	brainfuck_add(state, instruction);
 	brainfuck_execute(state->root, context);
	brainfuck_destroy_context(context);
 	brainfuck_destroy_state(state);
    printf("\n");
 	return EXIT_SUCCESS;
}

/*
 * Run the brainfuck interpreter in interactive mode.
 */
void run_interactive_console() {
	printf("brainfuck %s (%s, %s)\n", BRAINFUCK_VERSION, __DATE__, __TIME__);
	BrainfuckState *state = brainfuck_state();
	BrainfuckExecutionContext *context = brainfuck_context(BRAINFUCK_TAPE_SIZE);
	BrainfuckInstruction *instruction;
	
	printf(">> ");
	while(1) {
		fflush(stdout);
		instruction = brainfuck_parse_stream_until(stdin, '\n');
		brainfuck_add(state, instruction);
		brainfuck_execute(instruction, context);
		printf("\n>> ");
	}
}

/* Command line options */
static struct option long_options[] = {
	{"help", no_argument, 0, 'h'},
	{"eval", required_argument, 0, 'e'},
	{0, 0, 0, 0}
};

/*
 * Main entry point of the program.
 *
 * @param argc The amount of arguments given.
 * @param argv The array with arguments.
 */
int main(int argc, char *argv[]) {
	int c;
	int i = 1;
	int option_index = 0;
	
	while (1) {
		option_index = 0;
		c = getopt_long (argc, argv, "he:",
                         long_options, &option_index);
		if (c == -1)
			break;
        
		switch (c) {
            case 0:
                if (long_options[option_index].flag != 0)
                    break;
                break;
            case 'h':
                print_usage();
                return EXIT_SUCCESS;
            case 'e':
                return run_string((char *) optarg);
            case '?':
                print_usage();
                return EXIT_FAILURE;
            default:
                abort();
		}
	}
	if (argc > 1) {
		while (i < argc)
			if (run_file(fopen(argv[i++], "r")) == EXIT_FAILURE)
				fprintf(stderr, "error: failed to read file %s\n", argv[i - 1]);
            else
                printf("\n");
	} else {
		// checks if someone is piping code or just calling it the normal way.
		if (isatty(fileno(stdin))) {
			run_interactive_console();
            printf("\n");
		} else {
			if (run_file(stdin) == EXIT_FAILURE)
				fprintf(stderr, "error: failed to read from stdin\n");
		}
	}
    
	return EXIT_SUCCESS;
}
