# 
# 
# dtmf-rcq
# 
# Copyright (C) 2011  Kristoff Bonne, ON1ARF
# This program is largy based on the program "ircDDB-mheard", written
# by Michael Dirska (DL1BFF).
# Copyright (C) 2010   Michael Dirska, DL1BFF (dl1bff@mdx.de)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 



CFLAGS=-Wall

LDLIBS=-lpcap

all: dtmf-rcq cp2dpl msg2dpl cmd2dpl


dtmf-rcq.c:
cp2dpl.c:
msg2dpl.c:
cmd2dpl.c:

dstar_dv.c: dstar_dv.h golay23.h

golay23.c: golay23.h


dtmf-rcq: dtmf-rcq.o dstar_dv.o golay23.o

cp2dpl: cp2dpl.o
msg2dpl: msg2dpl.o
cmd2dpl: cmd2dpl.o



clean:
	rm -f *.o

dist-clean: clean
	rm -f dtmf-rcq

test_dv: test_dv.o dstar_dv.o golay23.o

# Installing: cp2dpl needs setuid priviledges to be able to
# write files in /dstar/tmp
install:
	install -o root -g root -m 755  dtmf-rcq /usr/bin/
	install -o root -g root -m 4755 cp2dpl /usr/bin/
	install -o root -g root -m 4755 cmd2dpl /usr/bin/
	install -o root -g root -m 4755 msg2dpl /usr/bin/

