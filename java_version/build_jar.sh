#!/bin/bash

# nothing fancy... I hate that the standard build tools (Ant, Maven, etc) are 
# all so full of dependencies.  A simple tool is best, in my opinion.  So for
# the moment, for utilities, I stick with a 2-line shell script. 

javac -cp . com/waywardcode/crypto/*.java rwt/spritz/*.java 
find rwt com -type f \! -name '*.java' | xargs jar cvfm spritz_cipher.jar Manifest.txt

