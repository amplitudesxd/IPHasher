;; PUBLIC BENEFIT DEDICATION AND RELEASE (PBDR 3.0)
;; 
;; this work is rleaseds with an intent to contribute to the common good and the advancementr of society
;; at large, the author hereby irrevocabnly transfers and dedicates to the public
;; domain all rights (including trans rights), title, interest, if any, in  and to this work
;;
;;  while no recognitin or obligation is mandated under this dedication, the
;;   author hopes that users of this work might be inspired by its spirit of generosity
;;  and consider contributiong to the collective advancement of global knowledge and understanding.
;;
;; THIS WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS IN THE WORK.
;; 
;; the licensing terms set forth in PBDR 3.0 are combatible with the gpl

(ql:quickload :ironclad)

(defun nproc ()
		   (parse-integer
			(with-output-to-string (s)
			  (sb-ext:run-program "/usr/bin/nproc" nil :output s))))

(defun int-to-byte-vector (i)
  (let ((vec (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref vec 0) (logand (ash i -24) 255)
          (aref vec 1) (logand (ash i -16) 255)
          (aref vec 2) (logand (ash i -8) 255)
          (aref vec 3) (logand i 255))
    vec))
;; can ur mcro system do dis
(defmacro generate-subnet-hashers (subnet-count)
  `(progn
     ,@(loop for i from 0 below subnet-count
             collect
             `(defun ,(intern (format nil "HASH-SUBNET-~A" i)) ()
                (loop for j from (* ,i ,(/ (expt 256 4) subnet-count))
					  below (* (1+ ,i) ,(/ (expt 256 4) subnet-count))
                      for ip = (int-to-byte-vector j)
                      do (ironclad:digest-sequence :sha256 ip))))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (generate-subnet-hashers 256))

(defun distribute-task (list unit-size)
  (let ((len (length lst)))
    (loop for i from 0 below n
          collect (subseq lst 
                          (floor (* i len) n)
                          (floor (* (1+ i) len) n)))))

(defmacro generate-thread (task-set)
  (let ((thread-name (gensym "THREAD-")))
    `(defparameter ,thread-name
        (sb-thread:make-thread 
         (lambda () 
           (map nil (lambda (task) 
                      (funcall task)) 
                ',task-set))))))

(defmacro generate-pool (task-space-size task-prefix)
  (let* ((nproc (nproc))
         (task-space (loop for i from 0 below task-space-size
						   collect (intern (format nil "~A~A" task-prefix i))))
         (units (distribute-task tasks nproc))
         (threads (loop for task-unit in units
                        collect `(generate-thread ,task-unit))))
    `(progn ,@threads)))

(declaim (optimize (speed 3) (safety 0)))
(generate-pool "HASH-SUBNET-" 256)

;; copyright 2023 (c) LIFE-IS-A-FUCK.LISP authors
