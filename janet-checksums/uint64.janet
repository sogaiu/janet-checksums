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

  (= (rsh (int/u64 "0xFF_FF_00_00_00_00_00_00") 48)
     (int/u64 "0xFF_FF"))
  # =>
  true

  (= (rsh (int/u64 "0x00_AB_CD_00") 0)
     (int/u64 "0x00_AB_CD_00"))
  # =>
  true

  )

# XXX: 0 <= n <= 64
(defn rrot
  [x n]
  # XXX: check that 0 <= n <= 64?
  (bor (rsh x n)
       (blshift x (- 64 n))))

(comment

  (= (rrot (int/u64 1) 1)
     (int/u64 "0x80_00_00_00_00_00_00_00"))
  # =>
  true

  (= (rrot (int/u64 1) 64)
     (int/u64 1))
  # =>
  true

  (= (rrot (int/u64 "0xFF_FF_00_00") 16)
     (int/u64 "0xFF_FF"))
  # =>
  true

  (= (rrot (int/u64 "0xFF_FF_00_00") 32)
     (int/u64 "0xFF_FF_00_00_00_00_00_00"))
  # =>
  true

  (= (rrot (int/u64 "0x00_AB_CD_00") 0)
     (int/u64 "0x00_AB_CD_00"))
  # =>
  true

  )

