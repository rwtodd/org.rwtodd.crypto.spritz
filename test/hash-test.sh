#!/bin/bash

# test a few hashes to make sure we got the right answer...

H=$(echo -n "arcfour" | ./spritz hash)
if [ "$H" == "/4zyaAlMh7lfdM5v7p0wA6X5/mlEZTzVDma/GJxj9pk=" ] 
then
   echo "ok (arcfour)"
else
   echo "ERROR! arcfour hash"
   exit 1
fi

H=$(echo -n "test of arc" | ./spritz hash -s 1024)
if [ "$H" == "mODbEBMQN0e4fNQkMpQAFXRnJb+m4qJ4Jj/ZD85JEnqkgx0guarutyDDNUC6kDvDCSnIIxW0md2v8fng9jwOgNZxmp46NaJxjoR1jNfDIa8zf6nWNUdypzFTYQwL34Ci/SWcRq78Kzvod+oGZSTvpMuznWPo2nzVY32LPY/CI4E=" ] 
then
   echo "ok (test of arc)"
else
   echo "ERROR! test of arc hash"
   exit 1
fi

H=$(echo -n "large-hash" | ./spritz hash -s 4096 | cut -c1-41)
if [ "$H" == "/51nef3y/1tdjXK2VFYoV/gSghU2nsOHLRoGnErF6" ]
then
   echo "ok (large-hash)"
else
   echo "ERROR! large-hash"
   exit 1
fi

echo "All tests pass"
