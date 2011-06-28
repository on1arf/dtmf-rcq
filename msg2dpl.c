// cpdpl: copies up to 20 characters of text to /dstar/tmp/message-<module>
// or /dstar/tmp/localmessage-module

// this application is designed to help secure the D-STAR voice-
// announcement and DTMF software package
// One of the ways a text-message can be played-out by a repeater
// is by using the Dplus package of Robin AA4RC
// This can be done by copying a text of up to 20 characters to 
// /dstar/tmp/message-<module> or /dstar/tmp/localmessage-<module>

// However, the directory /dstar/tmp is owned by root and the
// file-priviledges is set up as such that non-root users cannot
// write in that directory
// Using this application with setuid priviledges, it is still
// possible to allow the voice-announcement or DTMF application to
// run as non-root and still be able to issue D-STAR messages

// copyright (C) 2011 Kristoff Bonne ON1ARF
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

// 22 nov. 2010: version 0.1.1. initial release
// 4  jan. 2011: version 0.1.2. add version number

#define VERSION "0.1.2"

// needed for strndup
#define _GNU_SOURCE

// standard integers
#include <stdint.h>

// reading and writing files
#include <stdio.h>

// "exit" function
#include <stdlib.h>

// string functions
#include <string.h>

// buffersize = 128K
#define BUFFERSIZE 131072


// functions located further down
static void usage ( char * );

int main (int argc, char ** argv) {

char module=0;
int localorbroadcast=-1;
char * paramin;

FILE * fileout;

char * dplusfilename[2];
dplusfilename[0]=strdup("/dstar/tmp/message-X");
dplusfilename[1]=strdup("/dstar/tmp/broadcastmessage-X");

if (argc < 4) {
	fprintf(stderr,"Error: at least 3 arguments needed.\n");
	usage(argv[0]);
	fprintf(stderr,"Info: version = %s\n",VERSION);
	exit(-1);
}; // end if

paramin=argv[1];

// check first character, if 'a' or 'A' -> module is 1
if ((paramin[0] == 'a') || (paramin[0] == 'A')) {
	module=0x61; // 'a' in ascii
}; // end if

// check first character, if 'b' or 'B' -> module is 2
if ((paramin[0] == 'b') || (paramin[0] == 'B')) {
	module=0x62; // 'b' in ascii
}; // end if

// check first character, if 'c' or 'C' -> module is 3
if ((paramin[0] == 'c') || (paramin[0] == 'C')) {
	module=0x63; // 'c' in ascii
}; // end if

if (module == 0) {
	fprintf(stderr,"Error: module must be 'a', 'b' or 'c'\n");
	usage(argv[0]);
	exit(-1);
}; // end if


// check 2nd parameter. Should be "l" for local messages or "b" for
// broadcast messages

paramin=argv[2];

// check first character, if 'l' or 'L'
if ((paramin[0] == 'l') || (paramin[0] == 'L')) {
	localorbroadcast=0;
}; // end if

// check first character, if 'b' or 'B'
if ((paramin[0] == 'b') || (paramin[0] == 'B')) {
	localorbroadcast=1;
}; // end if

if (localorbroadcast == -1) {
	fprintf(stderr,"Error: Local-or-Broadcast parameter must be 'l' or 'b'\n");
	usage(argv[0]);
	exit(-1);
}; // end if


// replace "X" in output file name with repeater 
dplusfilename[0][19]=module;
dplusfilename[1][28]=module;


fileout=fopen(dplusfilename[localorbroadcast],"w");

if (fileout == NULL) {
	fprintf(stderr,"Error: cannot open output file %s\n",dplusfilename[localorbroadcast]);
	exit(-1);
}; // end if

// write up to 20 characters
fprintf(fileout,"%s\n",strndup(argv[3],20));
fclose(fileout);

return(0);
}; // end main program


// function "usage"
static void usage(char * argv0) {
	fprintf(stderr,"Usage: %s module {l,b} \"message\"\n",argv0);
}; // 
