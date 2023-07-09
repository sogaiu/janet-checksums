(defn deprintf
  [fmt & args]
  (when (os/getenv "VERBOSE")
    (eprintf fmt ;args)))

# only works up through 8 bytes
(defn encode-as-le
  [bytes]
  (var num (int/u64 0))
  (for i 0 (length bytes)
    (+= num
        (blshift (int/u64 (get bytes i))
                 (* i 8))))
  num)

(comment

  (encode-as-le [0x01 0x23 0x45 0x67])
  # =>
  (int/u64 "1732584193")

  (encode-as-le [0x89 0xab 0xcd 0xef])
  # =>
  (int/u64 "4023233417")

  (encode-as-le [0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef])
  # =>
  (int/u64 "17279655951921914625")

  )

# produces array of int/u64...better to be array of ordinary janet numbers?
(defn decode-le
  [num]
  (def n 4)
  (var tot num)
  (def res @[])
  (loop [i :down-to [(dec n) 0]]
    (def factor (math/exp2 (* i 8)))
    (def amt (div tot factor))
    (array/push res amt)
    (-= tot (* amt factor)))
  #
  (reverse! res))

(comment

  (decode-le (int/u64 "0x100"))
  # =>
  @[(int/u64 0) (int/u64 1) (int/u64 0) (int/u64 0)]

  (decode-le (int/u64 "0x67452301"))
  # =>
  @[(int/u64 0x01) (int/u64 0x23) (int/u64 0x45) (int/u64 0x67)]

  (decode-le (int/u64 "0xefcdab89"))
  # =>
  @[(int/u64 0x89) (int/u64 0xab) (int/u64 0xcd) (int/u64 0xef)]

  )

# only works up through 8 bytes
(defn encode-as-be
  [bytes]
  (def n-bytes (length bytes))
  (var num (int/u64 0))
  (loop [i :down-to [(dec n-bytes) 0]]
    (+= num
        (blshift (int/u64 (get bytes i))
                 (* (dec (- n-bytes i)) 8))))
  num)

(comment

  (encode-as-be [0x01 0x23 0x45 0x67])
  # =>
  (int/u64 "0x01234567")

  (encode-as-be [0x89 0xab 0xcd 0xef])
  # =>
  (int/u64 "0x89abcdef")

  (encode-as-be [0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef])
  # =>
  (int/u64 "0x0123456789abcdef")

  )

# produces array of int/u64...better to be array of ordinary janet numbers?
(defn decode-be
  [num]
  (def n 4)
  (var tot num)
  (def res @[])
  (loop [i :range [0 n]]
    (def factor (math/exp2 (* (dec (- n i)) 8)))
    (def amt (div tot factor))
    (array/push res amt)
    (-= tot (* amt factor)))
  #
  res)

(comment

  (decode-be (int/u64 "0x100"))
  # =>
  @[(int/u64 0) (int/u64 0) (int/u64 1) (int/u64 0)]

  (decode-be (int/u64 "0x67452301"))
  # =>
  @[(int/u64 0x67) (int/u64 0x45) (int/u64 0x23) (int/u64 0x01)]

  (decode-be (int/u64 "0xefcdab89"))
  # =>
  @[(int/u64 0xef) (int/u64 0xcd) (int/u64 0xab) (int/u64 0x89)]

  )

