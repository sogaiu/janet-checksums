(import ./utils :as u)
(import ./uint32)
(import ./uint64)

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
(def k-32-tbl
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

  (deep= k-32-tbl K-from-RFC)
  # =>
  true

  )

(defn length-as-8-bytes
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

  (length-as-8-bytes 1)
  # =>
  @[0 0 0 0 0 0 0 0x01]

  (length-as-8-bytes 3)
  # =>
  @[0 0 0 0 0 0 0 0x03]

  (length-as-8-bytes 496)
  # =>
  @[0 0 0 0 0 0 0x01 0xf0]

  )

(defn hex-out-8
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
    (length-as-8-bytes msg-len-in-bits))

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
                     (get k-32-tbl t)))
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
                       i t (hex-out-8 [a b c d e f g h] true))))

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
                     i (hex-out-8 [h0 h1 h2 h3 h4 h5 h6 h7] true)))

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

  (hex-out-8 res-bytes))

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

(defn sha-224
  [message]
  # the second 32-bits of the fractional parts of the square roots of
  # the 9th through 16th prime numbers.  n.b. that the constants are
  # arrived at in this fashion is not mentioned in the rfc nor in fips
  # 180-4
  (def init-hash-val
    # unclear how to compute these using janet's primitives.  the
    # first 32-bits can be obtained via operations on int/u64 numbers
    # but the tail ends of the second 32-bits might not be available
    # in a straight-forward fashion.  this is because the direct
    # initial computation involves arriving at "the factional parts of
    # the square roots of ... prime numbers" and then truncating.
    [(int/u64 "0xc1059ed8")
     (int/u64 "0x367cd507")
     (int/u64 "0x3070dd17")
     (int/u64 "0xf70e5939")
     (int/u64 "0xffc00b31")
     (int/u64 "0x68581511")
     (int/u64 "0x64f98fa7")
     (int/u64 "0xbefa4fa4")])

  (def res-bytes
    (sha-2-32 init-hash-val message))

  (array/pop res-bytes)

  (hex-out-8 res-bytes))

(comment

  (sha-224 "abc")
  # =>
  "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"

  (sha-224 "abcde")
  # =>
  "bdd03d560993e675516ba5a50638b6531ac2ac3d5847c61916cfced6"

  (sha-224 "abcdbcdecdefdefgefghfghighijhi")
  # =>
  "92c9be409b247f582a829a5717fc67e233e003ed7ba6f892e9358f01"

  (sha-224 "jkijkljklmklmnlmnomnopnopq")
  # =>
  "cae09129d828d03f60ce06115346a7e281cdb198ec61fff40b9ba1db"

  (sha-224 (string "abcdbcdecdefdefgefghfghighijhi"
                   "jkijkljklmklmnlmnomnopnopq"))
  # =>
  "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"

  )

(def k-64-tbl
  (seq [i :in ["428a2f98d728ae22" "7137449123ef65cd" "b5c0fbcfec4d3b2f"
               "e9b5dba58189dbbc" "3956c25bf348b538" "59f111f1b605d019"
               "923f82a4af194f9b" "ab1c5ed5da6d8118" "d807aa98a3030242"
               "12835b0145706fbe" "243185be4ee4b28c" "550c7dc3d5ffb4e2"
               "72be5d74f27b896f" "80deb1fe3b1696b1" "9bdc06a725c71235"
               "c19bf174cf692694" "e49b69c19ef14ad2" "efbe4786384f25e3"
               "0fc19dc68b8cd5b5" "240ca1cc77ac9c65" "2de92c6f592b0275"
               "4a7484aa6ea6e483" "5cb0a9dcbd41fbd4" "76f988da831153b5"
               "983e5152ee66dfab" "a831c66d2db43210" "b00327c898fb213f"
               "bf597fc7beef0ee4" "c6e00bf33da88fc2" "d5a79147930aa725"
               "06ca6351e003826f" "142929670a0e6e70" "27b70a8546d22ffc"
               "2e1b21385c26c926" "4d2c6dfc5ac42aed" "53380d139d95b3df"
               "650a73548baf63de" "766a0abb3c77b2a8" "81c2c92e47edaee6"
               "92722c851482353b" "a2bfe8a14cf10364" "a81a664bbc423001"
               "c24b8b70d0f89791" "c76c51a30654be30" "d192e819d6ef5218"
               "d69906245565a910" "f40e35855771202a" "106aa07032bbd1b8"
               "19a4c116b8d2d0c8" "1e376c085141ab53" "2748774cdf8eeb99"
               "34b0bcb5e19b48a8" "391c0cb3c5c95a63" "4ed8aa4ae3418acb"
               "5b9cca4f7763e373" "682e6ff3d6b2b8a3" "748f82ee5defb2fc"
               "78a5636f43172f60" "84c87814a1f0ab72" "8cc702081a6439ec"
               "90befffa23631e28" "a4506cebde82bde9" "bef9a3f7b2c67915"
               "c67178f2e372532b" "ca273eceea26619c" "d186b8c721c0c207"
               "eada7dd6cde0eb1e" "f57d4f7fee6ed178" "06f067aa72176fba"
               "0a637dc5a2c898a6" "113f9804bef90dae" "1b710b35131c471b"
               "28db77f523047d84" "32caab7b40c72493" "3c9ebe0a15c9bebc"
               "431d67c49c100d4c" "4cc5d4becb3e42b6" "597f299cfc657e2a"
               "5fcb6fab3ad6faec" "6c44198c4a475817"]]
    (int/u64 (string/format "0x%s" i))))

(defn length-as-16-bytes
  [len-in-bits]
  (var tot len-in-bits)
  (def res @[])
  (loop [i :down-to [(dec 16) 0]]
    (def factor (math/exp2 (* i bits-per-byte)))
    (def amt (div tot factor))
    (array/push res amt)
    (-= tot (* amt factor)))
  #
  res)

(comment

  (length-as-16-bytes 1)
  # =>
  @[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0x01]

  (length-as-16-bytes 3)
  # =>
  @[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0x03]

  (length-as-16-bytes 496)
  # =>
  @[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0x01 0xf0]

  )

(defn hex-out-16
  [words &opt dbg]
  (default dbg false)
  # each element of words has 64-bit be content
  (-> (seq [w :in words]
        # left pad with 0 if needed, want total of 16 chars per
        (string/format "%016x" w))
      (string/join (if dbg " " ""))))

(defn sha-2-64
  [init-hash-val message]
  (u/deprintf "\nmessage: %s" message)

  (def msg-len-in-bits
    (* (length message) bits-per-byte))

  # XXX: error out if message length (bits) is >= 2^128
  #      lol, like this is ever going to handle anything of that size...
  (assert (< msg-len-in-bits (math/exp2 128))
          (string/format "too long message length: %d bits"
                         msg-len-in-bits))

  (u/deprintf "%d bit (%d bytes) message length"
              msg-len-in-bits (length message))

  (def block-size-in-bits 1024)

  (def block-size-in-bytes
    (/ block-size-in-bits bits-per-byte))

  (def pad-len-in-bits
    (let [len-bits-space 128
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
    (length-as-16-bytes msg-len-in-bits))

  (u/deprintf "%d bytes for length bits" (length len-as-bytes))

  (def padded-msg
    (buffer/push @""
                 # message
                 message
                 # padding bits
                 ;padding-bytes
                 # length as bits modulo 2^128
                 ;len-as-bytes
                 ))

  (u/deprintf "padded-msg: %p" padded-msg)

  (def bytes-in-padded-msg
    (length padded-msg))

  (u/deprintf "%d bytes in padded message" bytes-in-padded-msg)

  (assert (zero? (mod bytes-in-padded-msg block-size-in-bytes))
          (string/format "padded msg len not a multiple of 1024 bits"))

  (defn choose
    [x y z]
    (bxor (band x y)
          (band (bnot x) z)))

  (defn majority
    [x y z]
    (bxor (band x y)
          (band x z)
          (band y z)))

  (defn big-sig-0
    [x]
    (bxor (uint64/rrot x 28)
          (uint64/rrot x 34)
          (uint64/rrot x 39)))

  (defn big-sig-1
    [x]
    (bxor (uint64/rrot x 14)
          (uint64/rrot x 18)
          (uint64/rrot x 41)))

  (defn small-sig-0
    [x]
    (bxor (uint64/rrot x 1)
          (uint64/rrot x 8)
          (uint64/rsh x 7)))

  (defn small-sig-1
    [x]
    (bxor (uint64/rrot x 19)
          (uint64/rrot x 61)
          (uint64/rsh x 6)))

  (def n-blocks
    (/ bytes-in-padded-msg block-size-in-bytes))

  (u/deprintf "%d 1024-bit block(s) in padded message" n-blocks)

  # express padded-msg as sequence of 8-byte / 64-bit (be) blocks
  (def m
    (seq [i :range [0 n-blocks]
          j :range [0 16] # XXX: name this 16?
          :let [start-idx (* 8 (+ (* i 16) j))
                end-idx (+ start-idx 8)]]
      (def buf (buffer/slice padded-msg start-idx end-idx))
      (u/encode-as-be buf)))

  (var [h0 h1 h2 h3 h4 h5 h6 h7] init-hash-val)

  (var [a b c d e f g h] [nil nil nil nil nil nil nil nil])

  (def w
    (array/new 80))

  (for i 0 n-blocks

    (array/clear w)

    (for j 0 16
      (array/push w
                  (get m (+ (* 16 i) j))))

    (for j 16 80
      (array/push w
                  (+ (small-sig-1 (get w (- j 2)))
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

    (for t 0 80
      (def t1
        (+ h
           (big-sig-1 e)
           (choose e f g)
           (get w t)
           (get k-64-tbl t)))
      (def t2
        (+ (big-sig-0 a)
           (majority a b c)))
      (set h g)
      (set g f)
      (set f e)
      (set e (+ d t1))
      (set d c)
      (set c b)
      (set b a)
      (set a (+ t1 t2))

      (u/deprintf
        (string/format "b: %d t: %02d ABCDEFGH: %s"
                       i t (hex-out-16 [a b c d e f g h] true))))

    (set h0 (+ h0 a))
    (set h1 (+ h1 b))
    (set h2 (+ h2 c))
    (set h3 (+ h3 d))
    (set h4 (+ h4 e))
    (set h5 (+ h5 f))
    (set h6 (+ h6 g))
    (set h7 (+ h7 h))

    (u/deprintf
      (string/format "end of block: %d H0 H1 H2 H3 H4 H5 H6 H7: %s"
                     i (hex-out-16 [h0 h1 h2 h3 h4 h5 h6 h7] true)))

    )

  @[h0 h1 h2 h3 h4 h5 h6 h7])

(defn sha-512
  [message]
  (def init-hash-val
    [(int/u64 "0x6a09e667f3bcc908")
     (int/u64 "0xbb67ae8584caa73b")
     (int/u64 "0x3c6ef372fe94f82b")
     (int/u64 "0xa54ff53a5f1d36f1")
     (int/u64 "0x510e527fade682d1")
     (int/u64 "0x9b05688c2b3e6c1f")
     (int/u64 "0x1f83d9abfb41bd6b")
     (int/u64 "0x5be0cd19137e2179")])

  (def res-bytes
    (sha-2-64 init-hash-val message))

  (hex-out-16 res-bytes))

(comment

  (sha-512 "abc")
  # =>
  (string "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")

  (sha-512 "abcde")
  # =>
  (string "878ae65a92e86cac011a570d4c30a7eaec442b85ce8eca0c2952b5e3cc0628c2"
          "e79d889ad4d5c7c626986d452dd86374b6ffaa7cd8b67665bef2289a5c70b0a1")

  (sha-512 "abcdbcdecdefdefgefghfghighijhi")
  # =>
  (string "6b22632a618b07bc6f18072e60648086a0c3f4220724f737f322606cbacee8ea"
          "510dc2970735072ca8e59f185f3a770a8948beb95dfe3bbbe18572ae6ec91f20")

  (sha-512 "jkijkljklmklmnlmnomnopnopq")
  # =>
  (string "f02d8e6b2649207bbfa0ca8fa9a667fc7673f9d23821ae59ac25c3939db9766b"
          "301cb61d0b6f56664d3b225b966dedfbf62281f4da7ebda8f13a2e2470a21a76")

  (sha-512 (string "abcdbcdecdefdefgefghfghighijhi"
                   "jkijkljklmklmnlmnomnopnopq"))
  # =>
  (string "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
          "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445")

  )

(defn sha-384
  [message]
  (def init-hash-val
    [(int/u64 "0xcbbb9d5dc1059ed8")
     (int/u64 "0x629a292a367cd507")
     (int/u64 "0x9159015a3070dd17")
     (int/u64 "0x152fecd8f70e5939")
     (int/u64 "0x67332667ffc00b31")
     (int/u64 "0x8eb44a8768581511")
     (int/u64 "0xdb0c2e0d64f98fa7")
     (int/u64 "0x47b5481dbefa4fa4")])

  (def res-bytes
    (sha-2-64 init-hash-val message))

  (array/pop res-bytes)

  (array/pop res-bytes)

  (hex-out-16 res-bytes))

(comment

  (sha-384 "abc")
  # =>
  (string "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
          "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")

  (sha-384 "abcde")
  # =>
  (string "4c525cbeac729eaf4b4665815bc5db0c84fe6300068a727c"
          "f74e2813521565abc0ec57a37ee4d8be89d097c0d2ad52f0")

  (sha-384 "abcdbcdecdefdefgefghfghighijhi")
  # =>
  (string "0eb6af2176a0934e1177b9ac961fb6ad62abbd301db9027f"
          "3a627c276ad7d6a028343233863a25e01e1b80ffb2d1f2a4")

  (sha-384 "jkijkljklmklmnlmnomnopnopq")
  # =>
  (string "4bd7b05260ddb6a61e55b8db2034af1c1e0c30c67cd26ccd"
          "61df3452f15b1a7a0b0702f06c922fd2eca30022685f6232")

  (sha-384 (string "abcdbcdecdefdefgefghfghighijhi"
                   "jkijkljklmklmnlmnomnopnopq"))
  # =>
  (string "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05ab"
          "fe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b")

  )

