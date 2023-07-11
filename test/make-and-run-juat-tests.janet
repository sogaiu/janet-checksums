(-> ["janet"
     "./janet-usages-as-tests/make-and-run-tests.janet"
     # specify file and/or directory paths relative to project root
     "./janet-checksums"
     "./usages"
     ]
    (os/execute :p)
    os/exit)

