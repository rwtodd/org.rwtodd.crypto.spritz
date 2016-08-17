; -- elisp implementation of the spritz cipher
; 
; Copyright Richard Todd. I put the code under the
; GPL v2.0.  See the LICENSE file in the repository.
; for more information.

(defun spritz-hash (fn sz)
  "Hashes a file of the user's choice."
  (interactive "fFilename:\np")
  (let ((realsz (if (> sz 1) sz 256)))
    (insert fn) (insert ": ")
    (spritz-disphash (spritz-hash-file fn realsz))
    (insert "\n")))


;; --- END OF INTERACTIVE FUNCTIONS. ---


(defun spritz-u8+ (&rest args) (logand (apply #'+ args) 255))

(defvar *reset-state* 
   (let ((vec (make-vector 256 0)))
     (dotimes (idx 256 vec)
       (aset vec idx idx))))

(defun make-spritz ()
  (spritz-reset (make-vector 7 0)))

(defun spritz-i (s) (aref s 0))
(defun spritz-set-i (s v) (aset s 0 v))
(defun spritz-j (s) (aref s 1))
(defun spritz-set-j (s v) (aset s 1 v))
(defun spritz-k (s) (aref s 2))
(defun spritz-set-k (s v) (aset s 2 v))
(defun spritz-z (s) (aref s 3))
(defun spritz-set-z (s v) (aset s 3 v))
(defun spritz-a (s) (aref s 4))
(defun spritz-set-a (s v) (aset s 4 v))
(defun spritz-w (s) (aref s 5))
(defun spritz-set-w (s v) (aset s 5 v))

(defun spritz-inca (s) 
  (aset s 4 (+ (aref s 4) 1)))
(defun spritz-incw (s) 
  (aset s 5 (spritz-u8+ (aref s 5) 1)))

(defun spritz-mem (s idx) (aref (aref s 6) idx)) 
(defun spritz-set-mem (s idx v) (aset (aref s 6) idx v))

(defun spritz-reset (s) 
  "makes a spritz vector new and empty"
  (fillarray s 0)
  (aset s 5 1) ;; set w to 1
  (aset s 6 (copy-sequence *reset-state*))
  s)

(defun spritz-swap (s i1 i2)
  "swaps two mem values in a spritz cipher"
   (let ((tmp (spritz-mem s i1)))
     (spritz-set-mem s i1 (spritz-mem s i2))
     (spritz-set-mem s i2 tmp)))

(defun spritz-crush (s) 
  (dotimes (i 128)
    (let ((other (- 255 i)))
      (if (> (spritz-mem s i) (spritz-mem s other))
	  (spritz-swap s i other)))))

(defun spritz-mem-at-sum (s v1 v2)
  (spritz-mem s (spritz-u8+ v1 v2)))

(defun spritz-update (s times) 
  (let ((i (spritz-i s))
	(j (spritz-j s))
	(k (spritz-k s))
	(w (spritz-w s))) 
    (dotimes (_ times)
      (setq i (spritz-u8+ i w))
      (setq j (spritz-u8+ k (spritz-mem-at-sum s j (spritz-mem s i))))
      (setq k (spritz-u8+ i k (spritz-mem s j)))
      (spritz-swap s i j))
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

(defun spritz-maybe-shuffle (s n)
  (if (>= (spritz-a s) n)
      (spritz-shuffle s)))

(defun spritz-absorb-nibble (s n)
  (spritz-maybe-shuffle s 128) 
  (spritz-swap s (spritz-a s) (spritz-u8+ 128 n))
  (spritz-inca s))

(defun spritz-absorb (s n)
  (spritz-absorb-nibble s (logand n 15))
  (spritz-absorb-nibble s (lsh n -4)))

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
	 (ans   (make-vector bytes 0)))
    (spritz-absorb-seq s seq)
    (spritz-absorb-stop s)
    (spritz-absorb s bytes)
    (spritz-squeeze s ans)))

(defun spritz-disphash (seq) 
  (mapc (lambda (v) (insert (format "%02x" v))) seq))

(defun spritz-read-binary-file (fn)
  (with-temp-buffer (insert-file-contents-literally fn)
		    (buffer-string)))  ; TODO -- consider buffer-substring-no-properties

(defun spritz-hash-file (fn sz)
  (spritz-hash-seq sz (spritz-read-binary-file fn))) 

(defun spritz-key-hash (iv key)
  (let ((s (make-spritz))
	(keybytes (spritz-hash-seq 1024 (string-as-unibyte key))))
    ;; absorb the IV
    (spritz-absorb-seq s iv)
    (spritz-absorb-stop s)
    ;; absorb the 1024-bit hashed key bytes
    (spritz-absorb-seq s keybytes)
    ;; now get the hash of the IV + key
    (spritz-squeeze s keybytes)
    ;; now, 5000 times, rehash...
    (dotimes (cnt 50 keybytes)
      (spritz-reset s)
      (spritz-absorb-seq s keybytes)
      (spritz-absorb-stop s)
      (spritz-absorb s 128)
      (spritz-squeeze s keybytes))))
   
(defun make-spritz-with-key (iv key) 
  (let ((keyhash (spritz-key-hash iv key))
	(s       (make-spritz)))
    (spritz-absorb-seq s keyhash)
    s))

(defun spritz-squeeze-xor-seq (s seq)
  (dotimes (idx (length seq) seq)
    (aset seq idx (logxor (aref seq idx)
			  (spritz-drip s)))))

(defun spritz-decrypt-file (fn pw)
  (let ((bindat (spritz-read-binary-file fn)))

    ;; step 1 .. check that first byte is 2
    (if (not (eql (aref bindat 0) 2))
	(error "File is in bad format!"))

    ;; step 2 ... generate a spritz stream with the IV and password,
    ;;            then decrypt the header and check it...
    (let* ((cipher (make-spritz-with-key (substring-no-properties bindat 1 5) pw))
	   (header (spritz-squeeze-xor-seq cipher (substring-no-properties bindat 5 14)))
	   (randhash (spritz-hash-seq 32 (substring-no-properties header 0 4))))
 
      (if (not (equal randhash 
		      (vconcat (substring-no-properties header 4 8))))
	  (error "Bad password or corrupted file!"))

      ;; step 3 ... skip the filename for now...
      (let* ((fname-length (aref header 8))
	     (idx          (+ 14 fname-length))
	     (fname        (spritz-squeeze-xor-seq cipher (substring-no-properties bindat 14 idx)))
	     (bindat-len   (length bindat)))
	
	;; step 4 ... decode the data...
	(while (< idx bindat-len)
	  (insert (logxor (aref bindat idx)
			  (spritz-drip cipher)))
	  (setq idx (+ 1 idx)))

	;; return the file name from within the file...
	fname))))


(defun spritz-load-file (fn pw)
  "Load an encrypted file."
  (interactive "fFilename:\nsPassword:")
  (switch-to-buffer (generate-new-buffer (file-name-nondirectory fn)))
  (let ((filename (spritz-decrypt-file fn pw)))
    (if (> (length filename) 0)
	(rename-buffer filename))))
    


(defun spritz-generate-random ()
  (vector (random 256) (random 256) (random 256) (random 256)))

(defun spritz-encrypt (fn pw)
  (interactive "FFilename:\nsPassword:")
  (let ((text (string-as-unibyte (buffer-string)))
	(basename (string-as-unibyte (file-name-nondirectory fn))))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      ;; first byte is 2
      (insert 2)
      
      ;; generate a random IV, random bytes, their hash, and the cipher stream
      (let* ((iv     (spritz-generate-random))
	     (rbytes (spritz-generate-random))
	     (hashed (spritz-hash-seq 32 rbytes))
	     (cipher (make-spritz-with-key iv pw)))
	(mapc #'insert iv)
	(mapc #'insert (spritz-squeeze-xor-seq cipher rbytes))
	(mapc #'insert (spritz-squeeze-xor-seq cipher hashed))
	
	;; now the filename...
	(insert (logxor (length basename) (spritz-drip cipher))) 
	(mapc #'insert (spritz-squeeze-xor-seq cipher basename))
	
	;; now the contents of the buffer...
	(mapc #'insert (spritz-squeeze-xor-seq cipher text)))

        ;; now write the file..
        (let ((coding-system-for-write 'raw-text-unix))
	  (write-file (concat fn ".dat"))))))
      
    
