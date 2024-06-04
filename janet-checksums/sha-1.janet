(import ./utils :as u)
(import ./uint32)

# sha-1 uses big endian (be), unlike md5 which uses little endian (le)

# https://www.ietf.org/rfc/rfc3174.txt

(def bits-per-byte 8)

(defn make-constant
  [n]
  (scan-number (string/format "0x%08x"
                              (math/trunc (* (math/exp2 30) (math/sqrt n))))))

# 2^30 times the square roots of 2, 3, 5 and 10.
(def k-tbl
  (array/concat @[]
                (array/new-filled 20 (make-constant 2))
                (array/new-filled 20 (make-constant 3))
                (array/new-filled 20 (make-constant 5))
                (array/new-filled 20 (make-constant 10))))

# md5 and sha-1 do this differently because of le vs be
(defn length-as-bytes
  [len-in-bits]
  (var tot len-in-bits)
  (def res @[])
  (loop [i :down-to [(dec 8) 0]]
    (def factor (math/exp2 (* i bits-per-byte)))
    (def amt (div tot factor))
    (array/push res amt)
    (-= tot (* amt factor)))
  #
  res)

(comment

  (length-as-bytes 1)
  # =>
  @[0 0 0 0 0 0 0 0x01]

  (length-as-bytes 3)
  # =>
  @[0 0 0 0 0 0 0 0x03]

  (length-as-bytes 496)
  # =>
  @[0 0 0 0 0 0 0x01 0xf0]

  )

(defn hex-out
  [a b c d e &opt dbg]
  (default dbg false)
  # a, b, c, d, e have 32-bit be content
  (-> (seq [w :in [a b c d e]]
        # left pad with 0 if needed, want total of 8 chars per
        (string/format "%08x" w))
      (string/join (if dbg " " ""))))

(defn sha-1-raw
  [message]
  (u/deprintf "\nmessage: %s" message)

  (def msg-len-in-bits
    (* (length message) bits-per-byte))

  # XXX: error out if message length (bits) is >= 2^64 - because we
  #      don't want to handle big things
  (assert (< msg-len-in-bits (math/exp2 64))
          (string/format "too long message length: %d bits"
                         msg-len-in-bits))

  (u/deprintf "%d bit (%d bytes) message length"
              msg-len-in-bits (length message))

  (def block-size-in-bits 512)

  (def block-size-in-bytes
    (/ block-size-in-bits bits-per-byte))

  (def pad-len-in-bits
    (let [len-bits-space 64
          partial-size (- block-size-in-bits len-bits-space)
          modded (mod msg-len-in-bits block-size-in-bits)]
      (if (< modded partial-size)
        (- partial-size modded)
        (+ (- block-size-in-bits modded) partial-size))))

  (u/deprintf "%d bits in padding length" pad-len-in-bits)

  # starts with a single 1 bit and is usually followed by multiple 0 bits
  (def padding-bytes
    @[0x80
      ;(array/new-filled (dec (/ pad-len-in-bits bits-per-byte))
                         0x00)])

  (u/deprintf "%d bytes in non-length padding" (length padding-bytes))

  (def len-as-bytes
    (length-as-bytes msg-len-in-bits))

  (u/deprintf "%d bytes for length bits" (length len-as-bytes))

  (def padded-msg
    (buffer/push @""
                 # message
                 message
                 # padding bits
                 ;padding-bytes
                 # length as bits modulo 2^64
                 ;len-as-bytes
                 ))

  (u/deprintf "padded-msg: %p" padded-msg)

  (def bytes-in-padded-msg
    (length padded-msg))

  (u/deprintf "%d bytes in padded message" bytes-in-padded-msg)

  (assert (zero? (mod bytes-in-padded-msg block-size-in-bytes))
          (string/format "padded msg len not a multiple of 512 bits"))

  (defn f
    [t b c d]
    (cond
      (<= 0 t 19)
      (bor (band b c)
           (band (uint32/flip b) d))
      #
      (<= 20 t 39)
      (bxor b c d)
      #
      (<= 40 t 59)
      (bor (band b c)
           (band b d)
           (band c d))
      #
      (<= 60 t 79)
      (bxor b c d)))

  (def n-blocks
    (/ bytes-in-padded-msg block-size-in-bytes))

  (u/deprintf "%d 512-bit block(s) in padded message" n-blocks)

  # express padded-msg as sequence of 4-byte / 32-bit (be) blocks
  (def m
    (seq [i :range [0 n-blocks]
          j :range [0 16] # XXX: name this 16?
          :let [start-idx (* 4 (+ (* i 16) j))
                end-idx (+ start-idx 4)]]
      (def buf (buffer/slice padded-msg start-idx end-idx))
      (u/encode-as-be buf)))

  (var [h0 h1 h2 h3 h4]
    [(int/u64 "0x67452301")
     (int/u64 "0xefcdab89")
     (int/u64 "0x98badcfe")
     (int/u64 "0x10325476")
     (int/u64 "0xc3d2e1f0")])

  (var [a b c d e] [nil nil nil nil nil])

  (def w
    (array/new 80))

  (for i 0 n-blocks

    (array/clear w)

    (for j 0 16
      (array/push w
                  (get m (+ (* 16 i) j))))

    (for j 16 80
      (array/push w
                  (uint32/lrot (bxor (get w (- j 3))
                                     (get w (- j 8))
                                     (get w (- j 14))
                                     (get w (- j 16)))
                               1)))

    (set a h0)
    (set b h1)
    (set c h2)
    (set d h3)
    (set e h4)

    (for t 0 80
      (def temp
        (uint32/plus (uint32/lrot a 5)
                     (f t b c d)
                     e
                     (get w t)
                     (get k-tbl t)))
      (set e d)
      (set d c)
      (set c (uint32/lrot b 30))
      (set b a)
      (set a temp)

      (u/deprintf
        (string/format "b: %d t: %02d ABCDE: %s"
                       i t (hex-out a b c d e true))))

    (set h0 (uint32/plus h0 a))
    (set h1 (uint32/plus h1 b))
    (set h2 (uint32/plus h2 c))
    (set h3 (uint32/plus h3 d))
    (set h4 (uint32/plus h4 e))

    (u/deprintf
      (string/format "end of block: %d H0 H1 H2 H3 H4: %s"
                     i (hex-out h0 h1 h2 h3 h4 true)))

    )

  [h0 h1 h2 h3 h4])

(comment

  (sha-1-raw "abc")
  # =>
  [(int/u64 "2845392438") (int/u64 "1191608682")
   (int/u64 "3124634993") (int/u64 "2018558572")
   (int/u64 "2630932637")]

  (hex-out (int/u64 "2845392438") (int/u64 "1191608682")
           (int/u64 "3124634993") (int/u64 "2018558572")
           (int/u64 "2630932637"))
  # =>
  "a9993e364706816aba3e25717850c26c9cd0d89d"

  )

(defn sha-1
  [message]
  (hex-out ;(sha-1-raw message)))

(comment

  (sha-1 "abc")
  # =>
  "a9993e364706816aba3e25717850c26c9cd0d89d"

  (sha-1 "abcde")
  # =>
  "03de6c570bfe24bfc328ccd7ca46b76eadaf4334"

  (sha-1 "abcdbcdecdefdefgefghfghighijhi")
  # =>
  "f9537c23893d2014f365adf8ffe33b8eb0297ed1"

  (sha-1 "jkijkljklmklmnlmnomnopnopq")
  # =>
  "346fb528a24b48f563cb061470bcfd23740427ad"

  (sha-1 (string "abcdbcdecdefdefgefghfghighijhi"
                 "jkijkljklmklmnlmnomnopnopq"))
  # =>
  "84983e441c3bd26ebaae4aa1f95129e5e54670f1"

  )

(defn raw-to-bytes
  [raw]
  (def buf @"")
  (each item raw
    (def bytes (int/to-bytes item))
    # the rightmost 4 bytes are always zero, ignore
    # also...big endian, so order reversed
    (buffer/push buf
                 (get bytes 3)
                 (get bytes 2)
                 (get bytes 1)
                 (get bytes 0)))
  #
  buf)

(comment

  (raw-to-bytes (sha-1-raw "abc"))
  # =>
  @"\xA9\x99>6G\x06\x81j\xBA>%qxP\xC2l\x9C\xD0\xD8\x9D"

  (raw-to-bytes [(int/u64 "2845392438") (int/u64 "1191608682")
                 (int/u64 "3124634993") (int/u64 "2018558572")
                 (int/u64 "2630932637")])
  # =>
  @"\xA9\x99>6G\x06\x81j\xBA>%qxP\xC2l\x9C\xD0\xD8\x9D"

  (map int/to-bytes [(int/u64 "2845392438") (int/u64 "1191608682")
                     (int/u64 "3124634993") (int/u64 "2018558572")
                     (int/u64 "2630932637")])
  # =>
  @[@"6>\x99\xA9\0\0\0\0"
    @"j\x81\x06G\0\0\0\0"
    @"q%>\xBA\0\0\0\0"
    @"l\xC2Px\0\0\0\0"
    @"\x9D\xD8\xD0\x9C\0\0\0\0"]

  )

(defn sha-1-bytes
  [message]
  (raw-to-bytes (sha-1-raw message)))

(comment

  (sha-1-bytes "abc")
  # =>
  @"\xA9\x99>6G\x06\x81j\xBA>%qxP\xC2l\x9C\xD0\xD8\x9D"

  )
