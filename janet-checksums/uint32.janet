# janet does not have unsigned 32-bit integers but does have unsigned
# 64-bit integers (int/u64).
#
# int/u64 has support for various bitwise and arithmetic operations
# including:
#
#   * addition
#   * bitwise and
#   * bitwise or
#   * bitwise not (complement)
#   * bitwise xor
#   * bitwise left shift
#
# the description in the ietf md5 rfc makes use of these types of
# operations along with a bitwise circular left rotate operation.
#
# the operations of `and`, `or`, and `xor` for int/u64 can probably be
# used without modification (assuming the very end result takes care
# to drop the top 32 bits, which should be all 0s assuming the
# original two operands had 0s for each of their top 32 bits).
#
# however, for addition, bitwise `not` (complement), and bitwise left
# shift, these can lead to bit 33 (or higher?) getting changed and
# potentially, this can affect the final results.  one way to account
# for this is to drop the top 32 bits after any of the aforementioned
# operations (including also the circular left rotate operation).
#
# this file contains some alternate functions that perform addition,
# bitwise `not` (complement), bitwise left shift, and bitwise circular
# left rotation, each followed by the dropping of the top 32 bits.
# this is accomplished by a bitwise and operation being applied with
# one operand set to `(int/u64 "0xFF_FF_FF_FF")`.  this is equivalent
# to performing an `and` with:
#
#   (int/u64 "0x00_00_00_00_FF_FF_FF_FF")

(defn plus
  [& xs]
  (var r (int/u64 0))
  (loop [x :in xs]
    (set r
         (band (int/u64 "0xFF_FF_FF_FF")
               (+ r x))))
  r)

(comment

  (= (plus (int/u64 1) (int/u64 2))
     (int/u64 3))
  # =>
  true

  (= (plus (int/u64 "0xFF_FF_FF_FF") (int/u64 2))
     (int/u64 1))
  # =>
  true

  (= (plus (int/u64 "0xFF_FF_FF_FF") (int/u64 "0xFF_FF_FF_FF"))
     (int/u64 "0xFF_FF_FF_FE"))
  # =>
  true

  (= (plus (int/u64 1) (int/u64 2) (int/u64 3))
     (int/u64 6))
  # =>
  true

  (= (plus (int/u64 "0xFF_FF_FF_FF") (int/u64 1) (int/u64 1))
     (int/u64 1))
  # => true

  )

(defn flip
  [x]
  (band (int/u64 "0xFF_FF_FF_FF")
        (bnot x)))

(comment

  (= (flip (int/u64 1))
     (dec (int/u64 "0xFF_FF_FF_FF")))
  # =>
  true

  (= (flip (int/u64 "0xFF_FF_FF_FF"))
     (int/u64 0))
  # =>
  true

  (= (flip (int/u64 "0x00_00_FF_FF"))
     (int/u64 "0xFF_FF_00_00"))
  # =>
  true

  (= (flip (int/u64 "0xF0_0F_F0_0F"))
     (int/u64 "0x0F_F0_0F_F0"))
  # =>
  true

  )

(defn lsh
  [x n]
  (band (int/u64 "0xFF_FF_FF_FF")
        (blshift x n)))

(comment

  (= (lsh (int/u64 1) 1)
     (int/u64 2))
  # =>
  true

  (= (lsh (int/u64 "0xFF_FF_00_00") 16)
     (int/u64 "0x00_00_00_00"))
  # =>
  true

  (= (lsh (int/u64 "0xFF_FF_00_00") 32)
     (int/u64 "0x00_00_00_00"))
  # =>
  true

  (= (lsh (int/u64 "0x00_AB_CD_00") 0)
     (int/u64 "0x00_AB_CD_00"))
  # =>
  true

  )

# XXX: 0 <= n <= 32
(defn lrot
  [x n]
  # XXX: check that 0 <= n <= 32?
  (bor (lsh x n)
       (brshift x (- 32 n))))

(comment

  (= (lrot (int/u64 1) 1)
     (int/u64 2))
  # =>
  true

  (= (lrot (int/u64 "0xFF_FF_00_00") 16)
     (int/u64 "0xFF_FF"))
  # =>
  true

  (= (lrot (int/u64 "0xFF_FF_00_00") 32)
     (int/u64 "0xFF_FF_00_00"))
  # =>
  true

  (= (lrot (int/u64 "0x00_AB_CD_00") 0)
     (int/u64 "0x00_AB_CD_00"))
  # =>
  true

  )

(defn rsh
  [x n]
  (brshift x n))

(comment

  (= (rsh (int/u64 1) 1)
     (int/u64 0))
  # =>
  true

  (= (rsh (int/u64 "0xFF_FF_00_00") 16)
     (int/u64 "0x00_00_FF_FF"))
  # =>
  true

  (= (rsh (int/u64 "0xFF_FF_00_00") 32)
     (int/u64 "0x00_00_00_00"))
  # =>
  true

  (= (rsh (int/u64 "0x00_AB_CD_00") 0)
     (int/u64 "0x00_AB_CD_00"))
  # =>
  true

  )

# XXX: 0 <= n <= 32
(defn rrot
  [x n]
  # XXX: check that 0 <= n <= 32?
  (bor (rsh x n)
       (band (int/u64 "0x00_00_00_00_FF_FF_FF_FF")
             (blshift x (- 32 n)))))

(comment

  (= (rrot (int/u64 1) 1)
     (int/u64 "0x80_00_00_00"))
  # =>
  true

  (= (rrot (int/u64 1) 32)
     (int/u64 1))
  # =>
  true

  (= (rrot (int/u64 "0xFF_FF_00_00") 16)
     (int/u64 "0xFF_FF"))
  # =>
  true

  (= (rrot (int/u64 "0xFF_FF_00_00") 32)
     (int/u64 "0xFF_FF_00_00"))
  # =>
  true

  (= (rrot (int/u64 "0x00_AB_CD_00") 0)
     (int/u64 "0x00_AB_CD_00"))
  # =>
  true

  )

