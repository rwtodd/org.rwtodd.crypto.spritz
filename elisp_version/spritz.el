; -- elisp implementation of the spritz cipher
; 
; Copyright Richard Todd. I put the code under the
; GPL v2.0.  See the LICENSE file in the repository.
; for more information.

(defun spritz-hash (fn sz)
  "Hashes a file of the user's choice and writes the hash to the
current buffer. The numeric argument gives the hash size in bits."
  (interactive "fFilename:\np")
  (let ((realsz (if (> sz 1) sz 256)))
    (insert fn) (insert ": ")
    (spritz-disphash (spritz-hash-file fn realsz))
    (insert "\n")))

(defun spritz-decrypt (fn pw)
  "Load an encrypted file with the given password."
  (interactive "fFilename:\nsPassword:")
  (let* ((filename (file-name-nondirectory fn))
	 (text 
	  (with-temp-buffer
	    (set-buffer-multibyte nil)
	    (let ((decrypted-filename (spritz-decrypt-file fn pw)))
	      (if (> (length decrypted-filename) 0)
		  (setq filename decrypted-filename)))
	    (string-as-multibyte (buffer-string)))))
    (switch-to-buffer (generate-new-buffer filename))
    (insert text)
    (goto-char (point-min))
    (normal-mode)))

(defun spritz-encrypt (fn pw)
  "Save the buffer encrypted to the given file with the given password."
  (interactive "FFilename:\nsPassword:")
  (let ((text (string-as-unibyte (buffer-string)))
	(basename (string-as-unibyte (file-name-nondirectory fn))))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      ;; first byte is 2 for v2
      (insert 2)
      
      ;; generate a random IV, random bytes, their hash, and the cipher stream
      (let* ((iv     (spritz-generate-random))
	     (rbytes (spritz-generate-random))
	     (hashed (spritz-hash-seq 32 rbytes))
	     (cipher (make-spritz-with-key iv pw *spritz-key-iterations-v2*)))
	(mapc #'insert iv)
	(mapc #'insert (spritz-squeeze-xor-seq cipher rbytes))
	(mapc #'insert (spritz-squeeze-xor-seq cipher hashed))
	
	;; now the filename...
	(insert (logxor (length basename) (spritz-drip cipher))) 
	(mapc #'insert (spritz-squeeze-xor-seq cipher basename))
	
	;; now the contents of the buffer...
	(mapc #'insert (spritz-squeeze-xor-seq cipher text)))

        ;; now write the file..
        (let ((coding-system-for-write 'binary))
	  (write-file (concat fn ".dat"))))))
      

;; --- END OF INTERACTIVE FUNCTIONS. ---


(defvar *reset-state* 
   (let ((vec (make-string 256 0)))
     (dotimes (idx 256 vec)
       (aset vec idx idx))))

(defun make-spritz ()
  (spritz-reset (make-vector 7 0)))

(eval-when-compile 
  (defmacro spritz-mem (s idx) `(aref (aref ,s 6) ,idx)) 
  (defmacro spritz-set-mem (s idx v) `(aset (aref ,s 6) ,idx ,v))

  (defmacro spritz-u8+ (&rest args) `(logand (+ ,@args) 255))
  (defmacro spritz-mem-at-sum (s &rest args)
    `(spritz-mem ,s (spritz-u8+ ,@args)))

  (defmacro spritz-i (s) `(aref ,s 0))
  (defmacro spritz-set-i (s v) `(aset ,s 0 ,v))
  (defmacro spritz-j (s) `(aref ,s 1))
  (defmacro spritz-set-j (s v) `(aset ,s 1 ,v))
  (defmacro spritz-k (s) `(aref ,s 2))
  (defmacro spritz-set-k (s v) `(aset ,s 2 ,v))
  (defmacro spritz-z (s) `(aref ,s 3))
  (defmacro spritz-set-z (s v) `(aset ,s 3 ,v))
  (defmacro spritz-a (s) `(aref ,s 4))
  (defmacro spritz-set-a (s v) `(aset ,s 4 ,v))
  (defmacro spritz-w (s) `(aref ,s 5))
  (defmacro spritz-set-w (s v) `(aset ,s 5 ,v))

  (defmacro spritz-inca (s) 
    `(aset ,s 4 (+ (aref ,s 4) 1)))

  (defmacro spritz-incw (s) 
    `(aset ,s 5 (spritz-u8+ (aref ,s 5) 1)))


  (defmacro spritz-swap (s i1 i2)
    "swaps two mem values in a spritz cipher"
    `(let ((tmp (spritz-mem ,s ,i1)))
       (spritz-set-mem ,s ,i1 (spritz-mem ,s ,i2))
       (spritz-set-mem ,s ,i2 tmp)))
  
)

(defun spritz-reset (s) 
  "makes a spritz vector new and empty"
  (fillarray s 0)
  (spritz-set-w s 1)
  (aset s 6 (copy-sequence *reset-state*))
  s)

(defun spritz-crush (s) 
  (dotimes (i 128)
    (let ((other (- 255 i)))
      (if (> (spritz-mem s i) (spritz-mem s other))
	  (spritz-swap s i other)))))


(defun spritz-update (s times) 
  (let ((i (spritz-i s))
	(j (spritz-j s))
	(k (spritz-k s))
	(w (spritz-w s))) 
    (dotimes (_ times)
      (setq i (spritz-u8+ i w))
      (let ((mem-i (spritz-mem s i)))
        (setq j (spritz-u8+ k (spritz-mem-at-sum s j mem-i)))
	(let ((mem-j (spritz-mem s j)))
          (setq k (spritz-u8+ i k mem-j))
          (spritz-set-mem s i mem-j)
          (spritz-set-mem s j mem-i))))
    (spritz-set-i s i)
    (spritz-set-j s j)
    (spritz-set-k s k)))

(defun spritz-gcd (e1 e2)
  (if (eql e2 0)
      e1
    (spritz-gcd e2 (mod e1 e2))))

(defun spritz-whip (s amt)
  (spritz-update s amt)
  (spritz-incw s)
  (while (not (eql 1 (spritz-gcd (spritz-w s) 256)))
    (spritz-incw s)))

(defun spritz-shuffle (s)
  (spritz-whip s 512)
  (spritz-crush s)
  (spritz-whip s 512)
  (spritz-crush s)
  (spritz-whip s 512)
  (spritz-set-a s 0))

(defmacro spritz-maybe-shuffle (s n)
  `(if (>= (spritz-a ,s) ,n)
      (spritz-shuffle ,s)))

(defun spritz-absorb-nibble (s n)
  (spritz-maybe-shuffle s 128) 
  (let ((n128 (spritz-u8+ 128 n))
        (sa   (spritz-a s)))
    (spritz-swap s sa n128)
    (spritz-inca s)))

(defmacro spritz-absorb (s n)
  `(progn 
     (spritz-absorb-nibble ,s (logand ,n 15))
     (spritz-absorb-nibble ,s (lsh ,n -4))))

(defun spritz-absorb-seq (s bytes)
  (mapc (lambda (v) (spritz-absorb s v)) bytes))

(defun spritz-absorb-stop (s)
  (spritz-maybe-shuffle s 128)
  (spritz-inca s))

(defun spritz-drip (s)
  (spritz-maybe-shuffle s 1)
  (spritz-update s 1)
  (spritz-set-z s 
		(spritz-mem-at-sum s 
				   (spritz-j s)
				   (spritz-mem-at-sum s
						      (spritz-i s)
						      (spritz-mem-at-sum s
									 (spritz-z s)
									 (spritz-k s))))))

(defun spritz-squeeze (s vec)
  (dotimes (idx (length vec))
    (aset vec idx (spritz-drip s)))
  vec)

(defun spritz-hash-seq (sz seq)
  (let* ((s     (make-spritz))
	 (bytes (/ (+ sz 7) 8))
	 (ans   (make-string bytes 0)))
    (spritz-absorb-seq s seq)
    (spritz-absorb-stop s)
    (spritz-absorb s bytes)
    (spritz-squeeze s ans)))

(defun spritz-disphash (seq) 
  (mapc (lambda (v) (insert (format "%02x" v))) seq))

(defun spritz-read-binary-file (fn)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert-file-contents-literally fn)
    (buffer-substring-no-properties (point-min) (point-max))))

(defun spritz-hash-file (fn sz)
  (spritz-hash-seq sz (spritz-read-binary-file fn))) 

(defun spritz-key-hash (iv key iterations)
  (let ((s (make-spritz))
	(keybytes (spritz-hash-seq 1024 (string-as-unibyte key))))
    ;; absorb the IV
    (spritz-absorb-seq s iv)
    (spritz-absorb-stop s)
    ;; absorb the 1024-bit hashed key bytes
    (spritz-absorb-seq s keybytes)
    ;; now get the hash of the IV + key
    (spritz-squeeze s keybytes)
    ;; now, many times, rehash...
    (dotimes (_ iterations keybytes)
      (spritz-reset s)
      (spritz-absorb-seq s keybytes)
      (spritz-absorb-stop s)
      (spritz-absorb-nibble s 0)   ;; manually break out (spritz-absorb s 128)
      (spritz-absorb-nibble s 8)
      (spritz-squeeze s keybytes))))
      
   
(defun make-spritz-with-key (iv key iterations) 
  (let ((keyhash (spritz-key-hash iv key iterations))
	(s       (make-spritz)))
    (spritz-absorb-seq s keyhash)
    s))

(defun spritz-squeeze-xor-seq (s seq)
  (dotimes (idx (length seq) seq)
    (aset seq idx (logxor (aref seq idx)
			  (spritz-drip s)))))

(defun spritz-decrypt-v1v2-header (bindat pw iterations)
  "Decrypts a v1 or v2 header from BINDAT, and key PW, iterating the keyhash ITERATIONS times.
It returns an assoc list with :cipher :idx :fname keys."
  (let* ((cipher (make-spritz-with-key (substring-no-properties bindat 1 5) pw iterations))
	 (header (spritz-squeeze-xor-seq cipher (substring-no-properties bindat 5 14)))
	 (randhash (spritz-hash-seq 32 (substring-no-properties header 0 4))))
 
    (if (not (equal randhash 
		    (substring-no-properties header 4 8)))
	(error "Bad password or corrupted file!"))

    ;; step 3 ... skip the filename for now...  
    (let* ((fname-length (aref header 8))
	   (idx          (+ 14 fname-length))
	   (fname        (spritz-squeeze-xor-seq cipher (substring-no-properties bindat 14 idx))))
      (list (cons :cipher cipher) (cons :idx idx) (cons :fname fname)))))      
    
(defun spritz-decrypt-file (fn pw)
  (let* ((bindat (spritz-read-binary-file fn))
	 (version (aref bindat 0))
	 (header  (cond
			 ((eql version 1) (spritz-decrypt-v1v2-header bindat pw 5000))
			 ((eql version 2) (spritz-decrypt-v1v2-header bindat pw 500))
			 (t                       (error "File is in a bad format!"))))
         (fname (cdr (assq :fname header)))
	 (idx   (cdr (assq :idx   header)))
	 (cipher (cdr (assq :cipher header)))
	 (bindat-len   (length bindat)))
	
    (while (< idx bindat-len)
      (insert (logxor (aref bindat idx)
		      (spritz-drip cipher)))
      (setq idx (+ 1 idx)))

    ;; return the file name from within the file...
    fname))

(defun spritz-generate-random ()
  (vector (random 256) (random 256) (random 256) (random 256)))
    
