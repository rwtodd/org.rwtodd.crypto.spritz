( vim: set filetype=forth : )

( Spritz State -- N.B. I depend on 8-bit CHARS )
CREATE SPRITZ-STATE 6 256 + CHARS ALLOT DOES> swap + ;
256 SPRITZ-STATE CONSTANT SI
257 SPRITZ-STATE CONSTANT SJ
258 SPRITZ-STATE CONSTANT SK
259 SPRITZ-STATE CONSTANT SZ
260 SPRITZ-STATE CONSTANT SA
261 SPRITZ-STATE CONSTANT SW

: init ( -- ) 
  256 0 DO I I SPRITZ-STATE c! LOOP
  0 SI c!  0 SJ c!  0 SK c!
  0 SZ c!  0 SA c!  1 SW c! ;

: state-swap ( i j -- ) 
     SPRITZ-STATE swap SPRITZ-STATE
     dup c@ -rot over c@ swap c! c! ; 

: gcd ( e1 e2 -- gcd ) 
   BEGIN dup 0<> WHILE tuck mod REPEAT drop ;

: c+ POSTPONE + 255 POSTPONE LITERAL POSTPONE AND ; immediate
: state-update ( n -- ) 
   0 DO
      SI c@ SW c@ c+ dup 2dup SI c! 
      SPRITZ-STATE c@ SJ c@ c+     
      SPRITZ-STATE c@ SK C@ tuck c+   dup dup >r SJ c!             
      SPRITZ-STATE c@ + + SK c!       r> state-swap       
   LOOP ;  

: whip ( -- ) 
   512 state-update BEGIN SW c@ 1+ dup SW c!  
                          256 gcd 1 = 
                    UNTIL ;

: crush ( -- ) 
   128 0 DO 
     I SPRITZ-STATE c@  255 I - SPRITZ-STATE c@ 
     >   IF  I    255 I -   state-swap  THEN
   LOOP ;

: shuffle ( -- ) whip crush whip crush whip  0 SA c! ;

: maybe-shuffle ( lim -- ) SA c@ < IF shuffle THEN ;

: absorb-nibble ( nibble -- )
   127 maybe-shuffle  128 +  SA c@ dup 1+ SA c!   state-swap ;
    
: absorb ( byte -- )
   dup 15    AND absorb-nibble  
        4 rshift absorb-nibble ;

: absorb-many ( addr u -- ) bounds DO I c@ absorb LOOP ;

: absorb-stop ( -- ) 127 maybe-shuffle   SA c@ 1+ SA c! ;

: (drip) ( -- byte ) 1 state-update 
    SK c@ SZ c@ c+ SPRITZ-STATE c@  
          SI c@ c+ SPRITZ-STATE c@
          SJ c@ c+ SPRITZ-STATE c@ dup SZ c!  ;

: drip ( -- byte )  0 maybe-shuffle (drip) ;

: drip-many ( addr u -- ) 
    0 maybe-shuffle  bounds DO (drip) I c! LOOP ;

: string-hash ( src/u dest/u -- )
   init    2swap absorb-many  
   absorb-stop  dup absorb 
   drip-many ;

: file-hash ( fname/u dest/u -- ) 
   init    2swap r/o bin open-file throw
   4096 allocate throw   { fileid buffer } 
      BEGIN buffer 4096 fileid read-file throw   
            dup 0> WHILE  buffer swap absorb-many
      REPEAT drop 
   buffer free throw
   fileid close-file throw
   absorb-stop dup absorb  drip-many ;


: print-hash ( src u -- ) 
    HEX 
      bounds DO I c@ 0 <<# # # #> type #>> LOOP 
    DECIMAL ; 

