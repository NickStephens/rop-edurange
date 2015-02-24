#!/usr/bin/env python

'''
This file contains function definitions for the vulnerable binary.
'''

preamble =\
"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

ssize_t sendstr(char *s);
ssize_t readlen(int fd, char *buf, size_t n);
void get_name(void);
void get_bio(void);
int main(void);
"""

''' the vulnerable function '''
vulnfunc =\
"""
void get_bio(void)
{
  char bio[%u];

  sendstr("Please give me a biography:\\n");
  gets(bio);

  sendstr("\\n");
  sendstr("New entry!\\n");
  printf("%%s:\\n%%s\\n", name, bio);
}
"""

routines ={\
'sendstr':\
"""
ssize_t sendstr(char *s)
{
  write(1, s, strlen(s));
}
""",
'readlen':\
"""
ssize_t readlen(int fd, char *buf, size_t n) {
    ssize_t rc;
    size_t nread = 0;
    char c;
    while (nread < n) {
        rc = read(fd, &c, 1);
        if (rc == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            break;
        }
        if (c == '\\n')
        {
            break;
        }
        *(buf + nread) = c;
        nread += rc;
    }
    return nread;
}
""",
'get_name':\
"""
void get_name(void)
{
  printf("Please give me a name for this biography entry: ");
  if(readlen(0, name, sizeof(name)) < 0)
  {
    sendstr("[-] read failed somehow, try again.\\n");
  }
}
""",
'main':\
"""
int main(void)
{
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  sendstr("Welcome to the terminal based biography app!\\n");
  sendstr("Written in C for speed!\\n\\n");

  get_name();
  get_bio();
}
"""}

''' routines which are not called, but add entropy to the binary '''
bloat = [\
"""
void list_entries(char *entry) 
{
	char lname[40];
	char bio[80];

	sendstr("[-] not supported.\\n");
}
""",
"""
char *allocate_entry(char *ename, char *bio)
{
	char *mentry;

	mentry = malloc(20 + 80);
	if (mentry == NULL)
	{
		perror("malloc");
		return NULL;
	}

	strcpy(mentry, ename);
	strcat(mentry, ": ");
	strcat(mentry, bio);

	return mentry;
}
""",
"""
int store_entry(char *ename, char *bio)
{
	int fd;

	fd = open("./bios", O_APPEND|O_CREAT, 0644);
	if (fd < 0)
	{
		perror("open");
		return 1;
	}

	write(fd, ename, strlen(ename));
	write(fd, bio, strlen(bio));

	return 0;
}
"""
]

libcfuncs =\
[\
"open(\"\", 0);",
"mmap((void *)0,0,0,0,0,0);",
"close(0);",
"mprotect((void *)0,0,0);",
"strncpy((char *)0,(char *)0, 0);",
"sprintf((char *)0,\"\");",
"time(0);",
"wait((void *)0);",
"signal(0,(void *)0);"\
]

ckeywords =\
[\
"auto",
"break",
"case",
"char",
"const",
"continue",
"default",
"do",
"double",
"else",
"enum",
"extern",
"float",
"for",
"goto",
"if",
"int",
"long",
"register",
"return",
"short",
"signed",
"sizeof",
"static",
"struct",
"switch",
"typedef",
"union",
"unsigned",
"void",
"volatile",
"while"\
]
