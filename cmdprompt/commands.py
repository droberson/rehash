import os
import sys

commands = []
commandhelp = []

# TODO exit, get, put
def prompt(sock):
    do_prompt = True
    print()

    while do_prompt == True:
        try:
            sys.stdout.write("rehash> ")
            cmdline_input = input()
            for valid_command in commands:
                if valid_command[0] == cmdline_input.split()[0]:
                    do_prompt = False
                    valid_command[1](sock, cmdline_input)
                    break
            if do_prompt == True:
                print("Invalid command: %s" % cmdline_input.split()[0])
        # Control-C and Control-D exit the program
        except (EOFError, KeyboardInterrupt):
            sock.close()
            exit(os.EX_OK)

