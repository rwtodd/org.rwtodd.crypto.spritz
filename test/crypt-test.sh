#!/bin/bash

# test that we can decrypt what we encrypt...
for tst in $(seq 20)
do
    PW=$(echo -n $RANDOM | ./spritz hash -s 72)
    TXT=$(echo -n $RANDOM | ./spritz hash -s $RANDOM)
    RESULT=$(echo -n "$TXT" | ./spritz crypt -p "$PW" | ./spritz crypt -d -p "$PW")
    if [ "$TXT" == "$RESULT" ]
    then
	echo "ok, encrypt-decrypt test number $tst"
    else
	echo "ERROR! encrypt-decrypt didn't match!"
	echo "PW: $PW"
	echo "TXT: $TXT"
	echo "RESULT: $RESULT"
	exit 1
    fi
done
