#! /bin/bash

#### Function "word2letters"
function word2letters {
word=$1

for (( i=0; i<${#word}; i++))
do
	echo -n "${word:$i:1}.ambe "
done 
}


#### Main program
module=$1
numpackets=$2
errors=$3
missing=$4

cd /home/dtmf/

pid=$$

ambe2dvtool.pl -t "T$numpackets E$errors M$missing" -o message$pid.dvtool statistics.ambe packets.ambe $(word2letters $numpackets) errors.ambe $(word2letters $errors) missing.ambe $(word2letters $missing) end.ambe

cp2dpl $module message$pid.dvtool
rm message$pid.dvtool
