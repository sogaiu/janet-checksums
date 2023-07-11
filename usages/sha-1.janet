(import ../janet-checksums/sha-1)

(comment

  (sha-1/sha-1 (buffer/new-filled 10000 (chr "a")))
  # =>
  "a080cbda64850abb7b7f67ee875ba068074ff6fe"

  (sha-1/sha-1 "01234567012345670123456701234567")
  # =>
  "c729c8996ee0a6f74f4f3248e8957edf704fb624"

  (sha-1/sha-1 (-> (seq [i :range [0 10]]
                     "01234567012345670123456701234567")
                   (string/join "")))
  # =>
  "a2b1377f3398e0696f4970e27edd5cfc475cf5bb"

  (= (sha-1/sha-1 (slurp "./data/1.pdf"))
     (sha-1/sha-1 (slurp "./data/2.pdf")))
  # =>
  true

  )
