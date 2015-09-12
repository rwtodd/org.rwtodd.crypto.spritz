( vim: set filetype=forth : )

( Spritz State -- N.B. I depend on 8-bit CHARS )
CREATE SPRITZ-STATE 6 256 + ALLOT DOES> + ;
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

: state-swap ( addr1 addr2 -- ) 
     POSTPONE dup POSTPONE c@ POSTPONE -rot 
     POSTPONE over POSTPONE c@ POSTPONE swap
     POSTPONE c! POSTPONE c! ; immediate

: gcd ( e1 e2 -- gcd ) 
   BEGIN dup 0<> WHILE tuck mod REPEAT drop ;

: c+ POSTPONE + 255 POSTPONE LITERAL POSTPONE AND ; immediate

( SW c@ SI c@  rot 
   0 DO
      over c+ dup dup       
      SPRITZ-STATE tuck c@  SJ c@ c+     
      SPRITZ-STATE c@ SK C@ tuck c+   dup SJ c!             
      SPRITZ-STATE dup >r c@ + + SK c! r> 
      state-swap 
   LOOP SI c! drop ;   )

: state-update ( n -- ) 
   SW c@ SI c@  rot 
   0 DO
      over c+ dup dup       
      SPRITZ-STATE tuck c@  SJ c@ c+     
      SPRITZ-STATE c@ SK C@ tuck c+   dup SJ c!             
      SPRITZ-STATE dup >r c@ + + SK c! r> 
      state-swap 
   LOOP SI c! drop ;  

: whip ( -- ) 512 state-update 
    SW c@ BEGIN 1+   dup 256 gcd 1 =  UNTIL SW c! ;

: crush ( -- ) 
   128 0 DO    
     255 I - SPRITZ-STATE I SPRITZ-STATE 2dup c@ swap c@
     >   IF state-swap ELSE 2drop THEN
   LOOP ;  

: shuffle ( -- ) whip crush whip crush whip  0 SA c! ;

: maybe-shuffle ( lim -- ) SA c@ < IF shuffle THEN ;

: absorb-nibble ( nibble -- )
   127 maybe-shuffle  128 + SPRITZ-STATE  SA c@ dup 1+ SA c! SPRITZ-STATE  
   state-swap ;
    
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

S" Amber_Diceless.djvu" PAD 32 file-hash PAD 32 cr print-hash bye
