/*

dtmf-rcq
DTMF decoder - Radio Channel Quality logger

Copyright (C) 2011 Kristoff Bonne, ON1ARF

This program is largy based on the program "ircDDB-mheard", written
by Michael Dirska (DL1BFF).
Copyright (C) 2010   Michael Dirska, DL1BFF (dl1bff@mdx.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <syslog.h>
#include <errno.h>

#include <unistd.h>

//#include "libutil.h"

#include "dstar_dv.h"


#define SYSLOG_PROGRAM_NAME "dtmf-rcq"

// include data-structures and global DEFINES
#include "dtmf-rcq.h"

// global vars
static struct dstar_mheard_info mheard_info[MAX_MODULE_ID];
static struct dstar_stream_info stream_info[MAX_MODULE_ID];
const char dtmf_chars[16] = "147*2580369#ABCD";

// time related values
struct timeval now;
struct timezone tz;

// list of functions
static void printdataline(int i, int datatype);
static void process_dv_data ( const u_char * data, int len );
static void process_packet ( const u_char * packet, int len );
static void usage(const char * a);







/// //////////////////////////////
/// MAIN PROGRAM /////////////////
/// //////////////////////////////


int main(int argc, char *argv[]) {

// location of argoption ("-i" or "-f"), arg1 (file/if) and arg2 (rules)
// by default set to 2 and 3 (if no "-t" option given)
int argoption=1;
int arg1=2;
int arg2=3;

// set track 
int track=-1;

// tempory var
int loop;

openlog (SYSLOG_PROGRAM_NAME, LOG_PID, LOG_DAEMON);

pcap_t *handle;

char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
struct pcap_pkthdr * header;
const u_char *packet;


if (argc < 2) {
		usage(argv[0]);
		return 1;
}; // end if

// check for "-t" option
if (strcmp("-t",argv[1]) == 0) {
	// if -t option is set, we need exact 6 arguments
	if (argc == 6) {
		track=atoi(argv[2]);
		
		// correct location of arguments in CLI
		argoption=3; arg1=4; arg2=5;
		
		if (track <1 ) {
			fprintf(stderr, "Error: Invalid frames parameter in track option\n");
			usage(argv[0]);
		return 1;
		}; // end if

	} else {
		usage(argv[0]);
		return 1;
	}; // end if
}; // end if

// just check number of arguments when -t" not set
if ((track == -1) && (argc!=4)) {
	usage(argv[0]);
	return 1;
}



if (strcmp("-f", argv[argoption]) == 0) {
// option -f -> read from cap-file
	handle = pcap_open_offline(argv[arg1], errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[arg1], errbuf);
		usage(argv[0]);
		return 2;
	}
} else if (strcmp("-i", argv[argoption]) == 0) {
// option -i -> read from interface
#define PKT_BUFSIZ 2000 
	handle = pcap_open_live(argv[arg1], PKT_BUFSIZ, 0, 500, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[arg1], errbuf);
		usage(argv[0]);
		return 2;
	}
} else {
// no options -f or -i -> error
	usage(argv[0]);
	return 3;
}; // end else - elsif - if


if (pcap_compile(handle, &fp, argv[arg2], 0, 0) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", argv[arg2], pcap_geterr(handle));
	usage(argv[0]);
	return 4;
}

if (pcap_setfilter(handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", argv[arg2], pcap_geterr(handle));
	usage(argv[0]);
	return 5;
}

int fd = pcap_get_selectable_fd(handle);

if (fd < 0) {
	fprintf(stderr, "Couldn't get file descriptor for select\n");
	return 6;
}

// clear "streamid" value in global streaminfo structure
// copy "track" parameter to global streaminfo structure
for (loop=0;loop<MAX_MODULE_ID;loop++) {
	stream_info[loop].stream_id=0;
	stream_info[loop].stream_config_track=track;

	stream_info[loop+MAX_MODULE_ID].stream_id=0;
	stream_info[loop+MAX_MODULE_ID].stream_config_track=track;

}; // end for

dstar_dv_init();


syslog(LOG_INFO, "start");

int count = 0;



// endless loop
while(1) {
	// setup structure for select, including timeout
	fd_set rfds;
	struct timeval tv;
	int retval;

	tv.tv_sec = 0;
	tv.tv_usec = SELECT_TIMEOUT;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	retval = select(fd + 1, &rfds, NULL, NULL, &tv);

	if (retval < 0) {
		syslog(LOG_ERR, "select failed, stop (errno=%d)", errno);
		break;
	}

	if (retval == 0) {
		continue;
	}

	count ++;

	int res = pcap_next_ex( handle, &header, &packet);

	if (res != 1) {
		if (res == -2) {
			break;
		}

		syslog(LOG_NOTICE, "pcap_next_ex: %d", res);
		continue;
	}
	process_packet(packet, header->len);

}

pcap_close(handle);
syslog(LOG_INFO, "stop");
return 0;
}; // end main program
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////


///////////////////////////////
// function usage
///////////////////////////////
static void usage(const char * a)
{
  fprintf (stderr, "Usage: %s [-t numframe] -f <pcap-file> <pcap rules>\n"
	"Usage: %s [-t numframe] -i <ethX> <pcap rules>\n", a, a);
}


///////////////////////////////
// function process_packet
///////////////////////////////
static void process_packet ( const u_char * packet, int len ) {
  const struct ethhdr * eh = (struct ethhdr *) packet;

  if (ntohs(eh->h_proto) != ETH_P_IP) {
    // unknown eth proto 
    return;
  }

  const struct iphdr * ih = (struct iphdr *) (packet + (sizeof (struct ethhdr)));

  if (ih->protocol != IPPROTO_UDP) {
    // unknown ip proto
    return;
  }

  const struct udphdr * uh = (struct udphdr *) (packet +
    (sizeof (struct ethhdr)) + (sizeof (struct iphdr)));

  int udp_len = ntohs(uh->len);


  if ((udp_len + (sizeof (struct ethhdr)) + (sizeof (struct iphdr))) > len) {
    // unexpected packet len 
    return;
  }



  const struct dstar_header * dh = (struct dstar_header *) (packet + ((sizeof (struct ethhdr))
        + (sizeof (struct iphdr)) + (sizeof (struct udphdr))));

  if (strncmp("DSTR", dh->dstar_id, 4) != 0) {
    // not a DSTR header
    return;
  }

  unsigned short dstar_data_len = ntohs(dh->dstar_data_len);

  if ((dstar_data_len + (sizeof(struct dstar_header))) != (udp_len - (sizeof (struct udphdr)))) {
    // unexpected dstar packet len 
    return;
  }

  if (dh->dstar_rs_flag != 0x73) {
    return;
  }

  const u_char * dstar_data = (u_char *) (packet + ((sizeof (struct ethhdr))
          + (sizeof (struct iphdr)) + (sizeof (struct udphdr))) + sizeof (struct dstar_header));


  switch (dh->dstar_pkt_type) {
    case DSTAR_PKT_TYPE_DV:
      process_dv_data (dstar_data, dstar_data_len);
      break;

    case DSTAR_PKT_TYPE_DD:
      break;

    case DSTAR_PKT_TYPE_MODULE_HEARD:
      break;

    case DSTAR_PKT_TYPE_NOP:
      break;

    default:
		// printf ("dstar type %02x unknown", dh->dstar_pkt_type);
      break;
  }


}; // end function process_packet


///////////////////////////////
// function process_dv_data
///////////////////////////////
static void process_dv_data ( const u_char * data, int len ) {

// error check, packet is correct size?
if (len < ((sizeof (struct dstar_dv_header)) + 1)) {
	return;
}

// initialise some vars
const struct dstar_dv_header * dh = (struct dstar_dv_header *) data;
// dv_type
// A B 0 C C C C C
// A=1 -> DV header freame
// B=1 -> DV stream, last frame
// C sequence number (0 to 20)
u_char dv_type = * (data + (sizeof (struct dstar_dv_header)));
const u_char * d = data + (sizeof (struct dstar_dv_header)) + 1;
u_short dv_stream_id = ntohs(dh->dv_stream_id);

// error checks
if (dh->dv_module >= MAX_MODULE_ID) {
	return;
}

struct dstar_stream_info * si = stream_info + dh->dv_module;
// struct dstar_mheard_info * mh = mheard_info + dh->dv_module;


// new stream ??? -> reinit
if (dv_stream_id != si->stream_id) {

	// unexpected new stream?
	if (si->stream_id != 0) {
		// send EXIT line
		printdataline( dh->dv_module, DTYPE_EXIT );
	}; 

	// new stream but not a DV-HEADER frame
	if (!(dv_type & 0x80)) {
		// get time information
		gettimeofday(&now,&tz);

		// not the begin of a stream: we missed the "BEGIN" frame
		printf("W;BMIS;%04X;%ld;%06ld;%d;\n",dv_stream_id,(long)now.tv_sec,(long)now.tv_usec,dh->dv_module);
	}; // end if

	// reinit vars
	si->stream_id = dv_stream_id;
	si->stream_counter = 0;
	si->stream_counter_track=si->stream_config_track;
	si->dstar_dv_errs = 0;
	si->dstar_dv_silent = 0;
	si->dstar_dv_missed = 0;
	si->dstar_dv_errs_track=0;
	si->dstar_dv_silent_track=0;
	si->dstar_dv_missed_track=0;
	si->dstar_last_dtmf=-1;
	si->dstar_last_seqnr=0xff;
	memset(si->dstar_last_textmsg,0,20);

}; // end (new stream)



if (dv_type & 0x80) {
// DV header
	si->sd_type = 0x00;

	// check on packet size
	if (len < ((sizeof (struct dstar_dv_header)) + 1 + (sizeof (struct dstar_dv_rf_header)))) {
		return;
	}

	const struct dstar_dv_rf_header * rh = (struct dstar_dv_rf_header *) d;

	if ((dv_type & 0x20) == 0) {
	// CRC OK
		struct dstar_mheard_info * mh = mheard_info + dh->dv_module;

		memcpy (mh->my_callsign, rh->my_callsign, sizeof mh->my_callsign);
		memcpy (mh->my_callsign_ext, rh->my_callsign_ext, sizeof mh->my_callsign_ext);
		memcpy (mh->your_callsign, rh->your_callsign, sizeof mh->your_callsign);
		memcpy (mh->rpt1_callsign, rh->rpt1_callsign, sizeof mh->rpt1_callsign);
		memcpy (mh->rpt2_callsign, rh->rpt2_callsign, sizeof mh->rpt2_callsign);
		memcpy (mh->flags, rh->flags, sizeof mh->flags);

		memset (mh->tx_msg, ' ', sizeof mh->tx_msg);

		// send "BEGIN" line
		printdataline( dh->dv_module, DTYPE_BEGIN);

	} else {
	// CRC NOT OK
		// print error-line
		printf("W;BCRC;%ld;%06ld;%d;\n",(long)now.tv_sec,(long)now.tv_usec,dh->dv_module);
	}


} else {
	// normal DV frame

	uint8_t thisseq=(dv_type & 0x1f);

	// error check on size
	if (len < ((sizeof (struct dstar_dv_header)) + 1 + (sizeof (struct dstar_dv_data)))) {
     	return;
	}

	// check sequence-numer
	// do we need to check?
	if (si->dstar_last_seqnr != 0xff) {
		if (!(((thisseq > 0) && ((thisseq - si->dstar_last_seqnr) == 1))
			|| ((thisseq == 0) && (si->dstar_last_seqnr == 20)))) {

			// frame(s) missing
			if (thisseq > si->dstar_last_seqnr) {
				// no wrap of sequence-numbers
				si->dstar_dv_missed += (thisseq - si->dstar_last_seqnr) -1;
				si->dstar_dv_missed_track += (thisseq - si->dstar_last_seqnr) -1;
			} else {
				si->dstar_dv_missed += (20 + thisseq - si->dstar_last_seqnr);
				si->dstar_dv_missed_track += (20 + thisseq - si->dstar_last_seqnr);
			}; // end else - if
		}; // end if (frame(s) missing
	}; // end if (test needed)

	// set new sequence-number
	si->dstar_last_seqnr = thisseq;


	if (dv_type & 0x40) {
	// end flag received
//		struct dstar_mheard_info * mh = mheard_info + dh->dv_module;

		printdataline( dh->dv_module, DTYPE_END);

		// reset counters
		si->stream_counter = 0;
		si->stream_counter_track=si->stream_config_track;
		si->stream_id=0;

		// zap lasttext info
		memset(&si->dstar_last_textmsg,0,20);

	} else {
		// data frame somewhere in the middle of the stream
  	   int data_pos = dv_type & 0x1F;

      const struct dstar_dv_data * dd = (struct dstar_dv_data *) d;



		int data[3];
		int errs = dstar_dv_decode( dd->dv_voice, data );

		// detected a silence frame
		if (data[0] == 0xf85) {
			si->dstar_dv_silent ++;
			si->dstar_dv_silent_track ++;
		}; // end (silence frame)

		// detected a DTMF tone
		if ((data[0] & 0x0ffc) == 0xfc0) {
			int dtmf = (data[0] & 0x03) | ((data[2] & 0x60) >> 3);

			// same DTMF-code as before?
			if (dtmf != si->dstar_last_dtmf) { 
			// nope

				// did we have a DTMF-code before?
				if (si->dstar_last_dtmf != -1) {
				// yes, send "end DTMF" line
					printf("D;%04X;X;%d;%d;\n", si->stream_id,si->stream_counter,errs);
				}; // end if

				// send "start DTMF" line
				printf("D;%04X;%c;%d;%d;\n", si->stream_id,dtmf_chars[dtmf],si->stream_counter,errs);
				fflush(stdout);
				si->dstar_last_dtmf=dtmf;

				// store number of error
				si->dstar_lowest_errs=errs;


			} else {
				// same DTMF-code as before: print line again if number of errors is lower then

				// dstar_lowest_errs
				if (errs < si->dstar_lowest_errs) {
					printf("D;%04X;%c;%d;%d;\n", si->stream_id,dtmf_chars[dtmf],si->stream_counter,errs);
					fflush(stdout);

					si->dstar_lowest_errs=errs;
				}; // end if


			}; // end else - if

  	   } else {
		// NOT a dtmf tone

			// was the previous frame a DTMF code?
			// if yes, print out a "end DTMF" line
			if (si->dstar_last_dtmf != -1) {
				printf("D;%04X;X;%d;%d;\n", si->stream_id,si->stream_counter,errs);
				fflush(stdout);
			}; 

			// reset lastdtmf values just to be sure
			si->dstar_last_dtmf=-1;
		}; // end else - if


		// addapt packet-counters and error-counters

		si->dstar_dv_errs += errs;
		si->dstar_dv_errs_track += errs;
		si->stream_counter ++ ;

		// tracking enabled?
		if (si->stream_config_track > 1) {
			si->stream_counter_track--;

			// 0 reached?
			if (si->stream_counter_track <= 0) {
				// yep, send "T" line
				printdataline( dh->dv_module , DTYPE_TRACK);
				// reset counters
				si->stream_counter_track=si->stream_config_track;
				si->dstar_dv_errs_track=0; si->dstar_dv_silent_track=0;
				si->dstar_dv_missed_track=0;
			}; // end if
		}; // end if


      int sd[3];

      sd[0] = dd->dv_slowdata[0] ^ 0x70;
  	   sd[1] = dd->dv_slowdata[1] ^ 0x4f;
     	sd[2] = dd->dv_slowdata[2] ^ 0x93;

		// if not "data syn frame" 
		if (!((sd[0] == 0x25) && (sd[1] == 0x1a) && (sd[2] == 0xc6)) 
		 	&& (data_pos != 0)) {
			int s_len = 0;
			int * s_ptr = sd;

			if ((data_pos & 0x01) == 0x01) {
				si->sd_type = sd[0];
				s_len = sd[0] & 0x07;
				if (s_len > 5) {
					s_len = 5;
				}


				if (s_len > 2) {
					s_len = 2; // print 2 bytes in from this packet
				}

				s_ptr ++; // first byte is type byte, skip it
			} else {
				s_len = si->sd_type & 0x07;
				if (s_len > 5) {
					s_len = 5;
				}

				if (s_len > 2) {
					s_len -= 2; // 2 bytes printed in previous packet
				} else {
					s_len = 0;
				}

			}

			switch (si->sd_type & 0xF0) {
  
				case 0x30:
					// printf ("User Data: ");
					break;

				case 0x40:
					if ((data_pos & 0x01) == 0x01) {
						s_len = 2;
						mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5] = sd[1];
						mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +1] = sd[2];
					} else {
						s_len = 3;
						mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +2] = sd[0];
						mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +3] = sd[1];
						mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +4] = sd[2];

						// check if text has changed
							if (data_pos == 8) {
								if (memcmp(&si->dstar_last_textmsg,&mheard_info[dh->dv_module].tx_msg,20)!=0) {
									printdataline( dh->dv_module, DTYPE_MESSAGE);
									// store new textmessage
									memcpy(&si->dstar_last_textmsg,&mheard_info[dh->dv_module].tx_msg,20);
								}; // end if
							}; // end if
					}

					break;

				case 0x50:
				//RF-Header
					break;

				case 0x60:
				//NOP
					s_len = 0;
					break;

				case 0xC0:
				//Code Squelch
					break;

				default:
					//printf ("UNKNOWN %02x: ", sd_type[dh->dv_module]);
					break;

			}; // end switch

		}; // end "not data sync frame"

	}; // end "frame in the middle of stream"
}; // end "DV frame"

}; // end function process_dv_data

///////////////////////////////
// function printdataline
///////////////////////////////
// dumps information
static void printdataline(int i, int datatype) {

// some tempory vars
struct dstar_mheard_info * mh = mheard_info + i;
struct dstar_stream_info * si = stream_info + i;
char s_my[9], s_my_e[5], s_yr[9], s_r1[9], s_r2[9], s_t[21];


memcpy(s_my,mh->my_callsign,8); s_my[8]=0x00;
memcpy(s_my_e,mh->my_callsign_ext,4); s_my_e[4]=0x00;
memcpy(s_yr,mh->your_callsign,8); s_yr[8]=0x00;
memcpy(s_r1,mh->rpt1_callsign,8); s_r1[8]=0x00;
memcpy(s_r2,mh->rpt2_callsign,8); s_r2[8]=0x00;
memcpy(s_t,mh->tx_msg,20); s_t[20]=0x00;


// get time information
gettimeofday(&now,&tz);

switch (datatype) {
	case DTYPE_BEGIN:
		// "BEGIN" message
		printf("B;%04X;%ld;%06ld;%d;%8s;%4s;%8s;%8s;%8s;%02X%02X%02X;\n",si->stream_id,(long)now.tv_sec,(long)now.tv_usec,i,s_my,s_my_e,s_yr,s_r1,s_r2,mh->flags[0],mh->flags[1],mh->flags[2]);
		break;

	case DTYPE_MESSAGE:
		// "MESSAGE/TEXT" message
		printf("M;%04X;%d;%20s;\n",si->stream_id,si->stream_counter,s_t);
		break;

	case DTYPE_END:
		// "END" message
		printf("E;%04X;%ld;%06ld;%d;%d;%d;%d;\n",si->stream_id,(long)now.tv_sec,(long)now.tv_usec,si->stream_counter,si->dstar_dv_silent,si->dstar_dv_errs,si->dstar_dv_missed);
		break;

	case DTYPE_EXIT:
		// "EXIT" message
		printf("E;%04X;%ld;%06ld;%d;%d;%d;%d;\n",si->stream_id,(long)now.tv_sec,(long)now.tv_usec,si->stream_counter,si->dstar_dv_silent,si->dstar_dv_errs,si->dstar_dv_missed);
		break;

	case DTYPE_TRACK:
		// "TRACK" message
		// only if "tracking" is enabled
		if (si->stream_config_track > 0) {
			printf("T;%04X;%ld;%06ld;%d;%d;%d;%d;\n",si->stream_id,(long)now.tv_sec,(long)now.tv_usec,si->stream_counter,si->dstar_dv_silent_track,si->dstar_dv_errs_track,si->dstar_dv_missed_track);
		}; // end if
		break;

}; // end switch


fflush(stdout);

}; // end function printdataline
