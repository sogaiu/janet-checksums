(import ./utils :as u)
(import ./uint32)

# md5 uses little endian (le)

# https://www.ietf.org/rfc/rfc1321.txt

(def bits-per-byte 8)

(def k-tbl
  (seq [i :range-to [1 64]
        :let [two-to-the-thirty-two (math/exp2 32)]]
    # same result as math/floor for non-negative numbers
    (math/trunc
      (* two-to-the-thirty-two
         (math/abs (math/sin i))))))

(comment

  (def T-from-RFC
    @[0xd76aa478 0xe8c7b756 0x242070db 0xc1bdceee
      0xf57c0faf 0x4787c62a 0xa8304613 0xfd469501
      0x698098d8 0x8b44f7af 0xffff5bb1 0x895cd7be
      0x6b901122 0xfd987193 0xa679438e 0x49b40821
      0xf61e2562 0xc040b340 0x265e5a51 0xe9b6c7aa
      0xd62f105d 0x2441453 0xd8a1e681 0xe7d3fbc8
      0x21e1cde6 0xc33707d6 0xf4d50d87 0x455a14ed
      0xa9e3e905 0xfcefa3f8 0x676f02d9 0x8d2a4c8a
      0xfffa3942 0x8771f681 0x6d9d6122 0xfde5380c
      0xa4beea44 0x4bdecfa9 0xf6bb4b60 0xbebfbc70
      0x289b7ec6 0xeaa127fa 0xd4ef3085 0x4881d05
      0xd9d4d039 0xe6db99e5 0x1fa27cf8 0xc4ac5665
      0xf4292244 0x432aff97 0xab9423a7 0xfc93a039
      0x655b59c3 0x8f0ccc92 0xffeff47d 0x85845dd1
      0x6fa87e4f 0xfe2ce6e0 0xa3014314 0x4e0811a1
      0xf7537e82 0xbd3af235 0x2ad7d2bb 0xeb86d391])

  (deep= k-tbl T-from-RFC)
  # =>
  true

  )

(def shift-table
  (array/concat @[]
                ;(seq [i :range [0 4]]
                   @[7 12 17 22])
                ;(seq [i :range [0 4]]
                   @[5 9 14 20])
                ;(seq [i :range [0 4]]
                   @[4 11 16 23])
                ;(seq [i :range [0 4]]
                   @[6 10 15 21])))

(comment

  (= 64 (length shift-table))
  # =>
  true

  (get shift-table 7)
  # =>
  22

  (get shift-table 26)
  # =>
  14

  (get shift-table 42)
  # =>
  16

  (get shift-table 51)
  # =>
  21

  )

# key is round number
(def block-word-index-table
  {0 [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15]
   1 [1 6 11 0 5 10 15 4 9 14 3 8 13 2 7 12]
   2 [5 8 11 14 1 4 7 10 13 0 3 6 9 12 15 2]
   3 [0 7 14 5 12 3 10 1 8 15 6 13 4 11 2 9]})

# XXX: happens to be similar to `decode-le`
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
  (reverse! res))

(comment

  (length-as-bytes 1)
  # =>
  @[1 0 0 0 0 0 0 0]

  (length-as-bytes 3)
  # =>
  @[3 0 0 0 0 0 0 0]

  (length-as-bytes 496)
  # =>
  @[240 1 0 0 0 0 0 0]

  )

(defn hex-out
  [a b c d &opt dbg]
  (default dbg false)
  (if-not dbg
    # a, b, c, d have 32-bit le content, need to reverse byte order for
    # each of a, b, c, d
    (-> (seq [w :in [a b c d]]
          # left pad with 0 if needed, want total of 2 chars per
          (-> (map |(string/format "%02x" $) (u/decode-le w))
              (string/join "")))
        (string/join ""))
    (-> (seq [w :in [a b c d]]
          # left pad with 0 if needed, want total of 8 chars per
          (string/format "%08x" w))
        (string/join " "))))

(defn md5
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

  (def block-words @[])

  (defn rn
    [a-fn]
    (fn [a b c d k s i]
      (uint32/plus b
                   (uint32/lrot (uint32/plus a
                                             (a-fn b c d)
                                             (get block-words k)
                                             (get k-tbl i))
                                s))))

  (defn big-f
    [b c d]
    (bor (band b c)
         (band (uint32/flip b) d)))

  (defn big-g
    [b c d]
    (bor (band b d)
         (band c (uint32/flip d))))

  (defn big-h
    [b c d]
    (bxor b c d))

  (defn big-i
    [b c d]
    (bxor c
          (bor b (uint32/flip d))))

  (def rnd-fns
    [(rn big-f)
     (rn big-g)
     (rn big-h)
     (rn big-i)])

  (def n-blocks
    (/ bytes-in-padded-msg block-size-in-bytes))

  (u/deprintf "%d 512-bit block(s) in padded message" n-blocks)

  # express padded-msg as sequence of 4-byte / 32-bit (le) blocks
  (def m
    (seq [i :range [0 n-blocks]
          j :range [0 16] # XXX: name this 16?
          :let [start-idx (* 4 (+ (* i 16) j))
                end-idx (+ start-idx 4)]]
      (def buf (buffer/slice padded-msg start-idx end-idx))
      (u/encode-as-le buf)))

  # little endian so byte order is least significant to most significant

  # word A: 01 23 45 67
  (def a0 (int/u64 "0x67452301"))
  # word B: 89 ab cd ef
  (def b0 (int/u64 "0xefcdab89"))
  # word C: fe dc ba 98
  (def c0 (int/u64 "0x98badcfe"))
  # word D: 76 54 32 10
  (def d0 (int/u64 "0x10325476"))

  (var [a b c d] [a0 b0 c0 d0])

  (var [aa bb cc dd] [nil nil nil nil])

  (for i 0 n-blocks

    (array/clear block-words)

    (for j 0 16
      (array/push block-words
                  (get m (+ (* 16 i) j))))

    (set aa a)
    (set bb b)
    (set cc c)
    (set dd d)

    (for rnd 0 4
      (def rnd-fn (get rnd-fns rnd))
      (for idx 0 16
        (def cnt (+ (* 16 rnd) idx))
        (def k (get-in block-word-index-table [rnd idx]))
        (def s (get shift-table cnt))
        (def r
             (rnd-fn a b c d
                     k s cnt))
        (set a d)
        (set d c)
        (set c b)
        (set b r)

        (u/deprintf
          (string/format "b: %d r: %d i: %02d ABCD: %s"
                         i rnd idx (hex-out a b c d true)))))

    (set a (uint32/plus a aa))
    (set b (uint32/plus b bb))
    (set c (uint32/plus c cc))
    (set d (uint32/plus d dd))

    (u/deprintf
      (string/format "end of block: %d ABCD: %s"
                     i (hex-out a b c d true)))

    )

  (hex-out a b c d))

(comment

  (md5 "")
  # =>
  "d41d8cd98f00b204e9800998ecf8427e"

  (md5 "a")
  # =>
  "0cc175b9c0f1b6a831c399e269772661"

  (md5 "abc")
  # =>
  "900150983cd24fb0d6963f7d28e17f72"

  (md5 "message digest")
  # =>
  "f96b697d7cb7938d525a2f31aaf161d0"

  (md5 "abcdefghijklmnopqrstuvwxyz")
  # =>
  "c3fcd3d76192e4007dfb496cca67e13b"

  (md5 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  # =>
  "d174ab98d277d9f5a5611c2c9f419d9f"

  (md5 (string "1234567890123456789012345678901234567890"
               "1234567890123456789012345678901234567890"))
  # =>
  "57edf4a22be3c955ac49da2e2107b67a"

  (md5 "The quick brown fox jumps over the lazy dog")
  # =>
  "9e107d9d372bb6826bd81d3542a419d6"

  (md5 "The quick brown fox jumps over the lazy dog.")
  # =>
  "e4d909c290d0fb1ca068ffaddf22cbd0"

  (md5 "The quick brown fox jumped over the lazy dog's back")
  # =>
  "e38ca1d920c4b8b8d3946b2c72f01680"

  (md5 "hello")
  # =>
  "5d41402abc4b2a76b9719d911017c592"

  )

