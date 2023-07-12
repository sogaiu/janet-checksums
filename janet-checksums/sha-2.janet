(import ./utils :as u)
(import ./uint32)

# sha-2 uses big endian (be)

# https://www.ietf.org/rfc/rfc6234.txt

(def bits-per-byte 8)

(def some-primes
  [2 3 5 7 11 13 17 19 23 29
   31 37 41 43 47 53 59 61 67 71
   73 79 83 89 97 101 103 107 109 113
   127 131 137 139 149 151 157 163 167 173
   179 181 191 193 197 199 211 223 227 229
   233 239 241 251 257 263 269 271 277 281
   283 293 307 311 313 317 331 337 347 349
   353 359 367 373 379 383 389 397 401 409])

# 5.1 of rfc
#
# the first 32 bits of the fractional parts of the cube roots of the
# first 64 prime numbers
(def k-tbl
  (seq [i :range [0 64]
        :let [cr (math/cbrt (get some-primes i))]]
    (->> (- cr (math/trunc cr))
         (* (math/exp2 32))
         math/trunc)))

(comment

  (def K-from-RFC
    @[0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b
      0x59f111f1 0x923f82a4 0xab1c5ed5 0xd807aa98 0x12835b01
      0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7
      0xc19bf174 0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc
      0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da 0x983e5152
      0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147
      0x06ca6351 0x14292967 0x27b70a85 0x2e1b2138 0x4d2c6dfc
      0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
      0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819
      0xd6990624 0xf40e3585 0x106aa070 0x19a4c116 0x1e376c08
      0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f
      0x682e6ff3 0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208
      0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2])

  (deep= k-tbl K-from-RFC)
  # =>
  true

  )

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
  [words &opt dbg]
  (default dbg false)
  # each element of words has 32-bit be content
  (-> (seq [w :in words]
        # left pad with 0 if needed, want total of 8 chars per
        (string/format "%08x" w))
      (string/join (if dbg " " ""))))

(defn sha-2-32
  [init-hash-val message]
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

  (defn choose
    [x y z]
    (bxor (band x y)
          (band (uint32/flip x) z)))

  (defn majority
    [x y z]
    (bxor (band x y)
          (band x z)
          (band y z)))

  (defn big-sig-0
    [x]
    (bxor (uint32/rrot x 2)
          (uint32/rrot x 13)
          (uint32/rrot x 22)))

  (defn big-sig-1
    [x]
    (bxor (uint32/rrot x 6)
          (uint32/rrot x 11)
          (uint32/rrot x 25)))

  (defn small-sig-0
    [x]
    (bxor (uint32/rrot x 7)
          (uint32/rrot x 18)
          (uint32/rsh x 3)))

  (defn small-sig-1
    [x]
    (bxor (uint32/rrot x 17)
          (uint32/rrot x 19)
          (uint32/rsh x 10)))

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

  (var [h0 h1 h2 h3 h4 h5 h6 h7] init-hash-val)

  (var [a b c d e f g h] [nil nil nil nil nil nil nil nil])

  (def w
    (array/new 64))

  (for i 0 n-blocks

    (array/clear w)

    (for j 0 16
      (array/push w
                  (get m (+ (* 16 i) j))))

    (for j 16 64
      (array/push w
                  (uint32/plus (small-sig-1 (get w (- j 2)))
                               (get w (- j 7))
                               (small-sig-0 (get w (- j 15)))
                               (get w (- j 16)))))

    (set a h0)
    (set b h1)
    (set c h2)
    (set d h3)
    (set e h4)
    (set f h5)
    (set g h6)
    (set h h7)

    (for t 0 64
      (def t1
        (uint32/plus h
                     (big-sig-1 e)
                     (choose e f g)
                     (get w t)
                     (get k-tbl t)))
      (def t2
        (uint32/plus (big-sig-0 a)
                     (majority a b c)))
      (set h g)
      (set g f)
      (set f e)
      (set e (uint32/plus d t1))
      (set d c)
      (set c b)
      (set b a)
      (set a (uint32/plus t1 t2))

      (u/deprintf
        (string/format "b: %d t: %02d ABCDEFGH: %s"
                       i t (hex-out [a b c d e f g h] true))))

    (set h0 (uint32/plus h0 a))
    (set h1 (uint32/plus h1 b))
    (set h2 (uint32/plus h2 c))
    (set h3 (uint32/plus h3 d))
    (set h4 (uint32/plus h4 e))
    (set h5 (uint32/plus h5 f))
    (set h6 (uint32/plus h6 g))
    (set h7 (uint32/plus h7 h))

    (u/deprintf
      (string/format "end of block: %d H0 H1 H2 H3 H4 H5 H6 H7: %s"
                     i (hex-out [h0 h1 h2 h3 h4 h5 h6 h7] true)))

    )

  @[h0 h1 h2 h3 h4 h5 h6 h7])

(defn sha-256
  [message]
  (def init-hash-val
    (seq [i :range [0 8]
          :let [sr (math/sqrt (get some-primes i))]]
      (->> (- sr (math/trunc sr))
           (* (math/exp2 32))
           math/trunc
           int/u64)))

  (def res-bytes
    (sha-2-32 init-hash-val message))

  (hex-out res-bytes))

(comment

  (sha-256 "abc")
  # =>
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

  (sha-256 "abcde")
  # =>
  "36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c"

  (sha-256 "abcdbcdecdefdefgefghfghighijhi")
  # =>
  "d578bbee0ee183a94170d4ff398cb29d06079a65101400771231f3fbb117c999"

  (sha-256 "jkijkljklmklmnlmnomnopnopq")
  # =>
  "fb29fa721adddc89b7b58e1c6a5577359f7e879c48672275617fe11ceb851d57"

  (sha-256 (string "abcdbcdecdefdefgefghfghighijhi"
                   "jkijkljklmklmnlmnomnopnopq"))
  # =>
  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

  )

