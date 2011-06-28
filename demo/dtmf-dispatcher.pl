#! /usr/bin/perl


# first load all perl modules we need

# exclusive file-locking mechanism
use Fcntl qw(:flock);

## Try to create and issue an exclusive lock on dtmf-dispatch.lck
## If it fails, there already is another instance of this
## program running

open (LOCKFILE,">/home/dtmf/dtmf-dispatcher.lck");

$lockresult=flock(LOCKFILE, LOCK_EX | LOCK_NB);

if ($lockresult == 0) {
        # lock failed, so there already is a instance of this program running
        # -> exit
        exit;
}; # end if




open (DTMFIN,"sudo /usr/bin/dtmf-rcq -i eth1 \"src host 172.16.0.1 and udp port 20000\"|");

while (<DTMFIN>) {
	$inpline=$_;
	chomp $inpline; # remove leading cr/lf if present

	($cmd,$streamid,$part3)=split(";",$inpline,3);

	if (($cmd eq "E") || ($cmd eq "X")) {
	# end of stream

		($timesec,$timeusec,$numpcks,$numsilent,$numerror,$nummissing,$dummy)=split(";",$part3,6);

		##### COMMANDS to execute
############
# Add code here for additional commands to be executed by DTMF keys ###
############

		# Do we know this stream?
		if (defined $module{$streamid}) {

			if (($fullkey{$streamid} eq "111") || (substr($call_yr{$streamid},7,1) eq "Q")){
			# DTMF code "111" or your-call is "       Q" -> play out announcement of number of packets, errors and missing
				system("/home/voiceann/dtmf/announcecounters.sh $module{$streamid} $numpcks $numerror $nummissing");

			} elsif ($fullkey{$streamid} eq '**') {
			# ** -> UNLINK
				system("/usr/bin/cmd2dpl $module{$streamid} \"       U\"");

			} elsif ($fullkey{$streamid} =~ m/^\*[0-9][0-9][0-9][A-C]/ ) {
			# *[0-9][0-9][0-9][A-C] -> link to reflector REFXXXY
				$reftxt="REF".substr($fullkey{$streamid},1,3).substr($fullkey{$streamid},4,1)."L";
				system("/usr/bin/cmd2dpl $module{$streamid} \"$reftxt\"");

			} elsif ($fullkey{$streamid} =~ m/^\*[0-9][0-9][0-9][1-3]/ ) {
			# *[0-9][0-9][0-9][1-3] -> link to reflector REFXXXY (Y is A-C based on y = 1-3)
				$reftxt="REF".substr($fullkey{$streamid},1,3).chr(substr($fullkey{$streamid},4,1)+64)."L";
				system("/usr/bin/cmd2dpl $module{$streamid} \"$reftxt\"");

			} elsif ($fullkey{$streamid} ne "") {
			# send message "unkown DTMF"
				system("/usr/bin/msg2dpl $module{$streamid} l 'UNK DTMF $fullkey{$streamid}'");
			}; # end if

		}; # end if (do we know this stream?)

##############
# code for DTMF actions ends here
# do not change anything below these lines unless you know what you are doing
##############

		# clear all vars for this stream
		undef $fullkey{$streamid}; undef $lastkey{$streamid};
		undef $lastkeypressed{$streamid}; undef $lastkeyunpressed{$streamid};
		undef $module{$streamid}; undef $call_yr{$streamid};

	} elsif ($cmd eq "B") {
	# beginning of stream
		($timesec,$timeusec,$controller,$mycall,$mycallext,$yourcall,$repcall1,$repcall2,$flags,$dummy)=split(";",$part3,10);

		# init vars
		$fulldtmf{$streamid}="";
		$lastkeydepressed{$streamid}=0; # timestamp last keydepress
		$module{$streamid}=substr($repcall1,7,1);
		$call_yr{$streamid}=$yourcall;
		undef $lastkeypressed{$streamid}; # timestamp last keypress
		undef $lastkey{$streamid}; # key pressed of last keypress

	} elsif ($cmd eq "D") {
	# dtmf pushed / released
		($dtmfkey,$framecounter,$errs,$dummy)=split(";",$part3,4);

		
		if ($dtmfkey ne "X") {
		# DTMFkey is not "X" -> key press
		$tdiff=$framecounter - $lastkeydepressed{$streamid};


			# there needs to be at least 300 ms (15 frames) between the end of the
			# last key-depress and the this key-press
			# only accept key is no errors
			if ((($framecounter - $lastkeydepressed{$streamid}) > 15 ) && ($errs == 0)) {
				$lastkey{$streamid}=$dtmfkey;
			};

			## if code is same as before and key-releasetime < 10 frames (200 ms),
			# We assume the previouis "release" was due to DTMF-decoding errors (bad packets).
			# so we do not set the "lastkeypressed" value
			if (($dtmfkey ne $lastkey{$streamid}) || ($tdiff > 10)) {
				$lastkeypressed{$streamid}=$framecounter;
			}; # end if

		} else {
		# DTMFkey = "X" -> key depress
			# a key needs to be pressed for at least 300 ms (15 frames) to be valid

			if (($framecounter - $lastkeypressed{$streamid}) > 15) {
				# add key to fullkey
				$fullkey{$streamid} .= $lastkey{$streamid};

				# reset lastkey
				undef $lastkey{$streamid};
			}; # end if

			# re-init vars
			$lastkeydepressed{$streamid}=$framecounter;

		}; # end else - if

	}; # end elsif - elsif - if

}; # end while

# end of program

