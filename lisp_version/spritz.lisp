;; S P R I T Z   C I P H E R

(defpackage :com.waywardcode.spritz
  (:use :common-lisp)
;;  (:export #:whatever)
  )

(in-package :com.waywardcode.spritz)

;; ss ==> "spritz state"
(defstruct ss
  (i 0 :type (unsigned-byte 8))
  (j 0 :type (unsigned-byte 8))
  (k 0 :type (unsigned-byte 8))
  (z 0 :type (unsigned-byte 8))
  (a 0 :type (unsigned-byte 8))
  (w 1 :type (unsigned-byte 8))
  (mem (let ((arr (make-array 256
			      :element-type '(unsigned-byte 8)
			      :initial-element 0)))
	 (dotimes (idx 256 arr)
	   (setf (aref arr idx) idx)))
       :type (array (unsigned-byte 8))))

;; take an existing ss struct and reset it to initial values
(defun reset (s)
  (setf (ss-i s) 0
	(ss-j s) 0
	(ss-k s) 0
	(ss-z s) 0
	(ss-a s) 0
	(ss-w s) 1)
  (dotimes (idx 256 s)
    (setf (aref (ss-mem s) idx) idx)))

(defun crush (s)
  (let ((arr (ss-mem s)))
    (dotimes (idx 128)
      (let ((other (- 255 idx)))
	(if (> (aref arr idx) (aref arr other))
	    (rotatef (aref arr idx) (aref arr other)))))))

(defmacro u8+ (&rest args) `(logand (+ ,@args) 255))
(defmacro mem-at-sum (s &rest args)
  `(aref (ss-mem ,s) (u8+ ,@args)))

(defun update (s times) 
  (let ((i (ss-i s))
	(j (ss-j s))
	(k (ss-k s))
	(w (ss-w s))
	(mem (ss-mem s))) 
    (dotimes (_ times)
      (setq i (u8+ i w))
      (let ((mem-i (aref mem i)))
        (setq j (u8+ k (mem-at-sum s j mem-i)))
	(let ((mem-j (aref mem j)))
          (setf k            (u8+ i k mem-j)
		(aref mem i) mem-j
		(aref mem j) mem-i))))
    (setf (ss-i s) i
	  (ss-j s) j
	  (ss-k s) k)))

(defun whip (s amt)
  (update s amt)
  (setf (ss-w s) (u8+ (ss-w s) 2)))

(defun shuffle (s)
  (whip s 512)
  (crush s)
  (whip s 512)
  (crush s)
  (whip s 512)
  (setf (ss-a s) 0))

(defmacro maybe-shuffle (s n)
  `(if (>= (ss-a ,s) ,n) (shuffle ,s)))

(defun absorb-nibble (s n)
  (maybe-shuffle s 128)
  (let ((mem (ss-mem s)))
    (rotatef (aref mem (ss-a s)) (aref mem (+ 128 n))))
  (incf (ss-a s)))

(defmacro absorb (s n)
  `(progn
     (absorb-nibble ,s (logand ,n 15))
     (absorb-nibble ,s (ash ,n -4))))

(defun absorb-vec (s bytes)
  (loop for b across bytes do
	(absorb s b)))

(defun absorb-stop (s)
  (maybe-shuffle s 128)
  (incf (ss-a s)))

(defun drip (s)
  (maybe-shuffle s 1)
  (update s 1)
  (setf (ss-z s) 
	(mem-at-sum s 
		    (ss-j s)
		    (mem-at-sum s
				(ss-i s)
				(mem-at-sum s
					    (ss-z s)
					    (ss-k s))))))

(defun squeeze (s vec)
  (dotimes (idx (length vec) vec)
    (setf (aref vec idx) (drip s))))

(defun absorb-int-bytes (s n)
  (if (> n 255)
      (absorb-int-bytes s (ash n -8)))
  (absorb s n))

(defun spritz-hash-seq (size seq)
  (let* ((s     (make-ss))
	 (bytes (floor (+ size 7) 8))
	 (ans   (make-array bytes
			    :element-type '(unsigned-byte 8)
			    :initial-element 0)))
    (absorb-vec s seq)
    (absorb-stop s)
    (absorb-int-bytes s bytes)
    (squeeze s ans)))



  

 
