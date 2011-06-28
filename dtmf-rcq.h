/*

dtmf-rcq

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

// DTMFFEC.H
// Data-structures and global DEFINES

struct dstar_header {
	char dstar_id[4];
	u_short dstar_pkt_num;
	u_char dstar_rs_flag;
	u_char dstar_pkt_type;
#define DSTAR_PKT_TYPE_DD   0x11
#define DSTAR_PKT_TYPE_DV   0x12
#define DSTAR_PKT_TYPE_MODULE_HEARD   0x21
#define DSTAR_PKT_TYPE_NOP   0x00
	u_short dstar_data_len;
};

struct dstar_dv_header {
	u_char dv_unknown1;
	u_char dv_unknown2;
	u_char dv_unknown3;
	u_char dv_module;
	u_short dv_stream_id;
};

struct dstar_dv_data {
	u_char dv_voice[9];
	u_char dv_slowdata[3];
};

struct dstar_dv_rf_header {
	u_char flags[3];
	char rpt2_callsign[8];
	char rpt1_callsign[8];
	char your_callsign[8];
	char my_callsign[8];
	char my_callsign_ext[4];
	u_char checksum[2];
};


struct dstar_mheard_info {
	u_char flags[3];
	char rpt2_callsign[8];
	char rpt1_callsign[8];
	char your_callsign[8];
	char my_callsign[8];
	char my_callsign_ext[4];
	char info_type;
	char tx_msg[20];
};

struct dstar_stream_info {
	int sd_type;
	int stream_id;
	int stream_counter;
	int stream_counter_track;
	int stream_config_track;
	int dstar_dv_errs;
	int dstar_dv_silent;
	int dstar_dv_missed;
	int dstar_dv_errs_track;
	int dstar_dv_silent_track;
	int dstar_dv_missed_track;
	int dstar_last_dtmf;
	int dstar_lowest_errs;
	uint8_t dstar_last_seqnr;
	char dstar_last_textmsg[20];
};

#define MAX_MODULE_ID 4


/* time to wait for tx msg:  MHEARD_INFO_TIMER * SELECT_TIMEOUT */
#define MHEARD_INFO_TIMEOUT 10
#define SELECT_TIMEOUT	  100000

#define DTYPE_BEGIN 0
#define DTYPE_MESSAGE 1
#define DTYPE_END 2
#define DTYPE_EXIT 3
#define DTYPE_TRACK 4

