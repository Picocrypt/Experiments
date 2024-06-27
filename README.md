# Goals

1. Create a stand alone backend that any frontend (gui, web, cli) should
   be able to use directly. This should enable all fontend tools to access
   the same general feature set and avoid chance of errors between tools.

2. Remove the use of tmp files. A normal user does not know that there are
   additional copies made, so if picocrypt were to crash at the wrong moment,
   they would not know to go find and clean up the tmp files. Add data saved
   to disk should exist only at the clear intended destination.

3. Make the encryption testable. At a minimum, each feature should have a
   full integration test, to prove that any changes to picocrypt still work.
   Ideally, there would be backwards compatibility testing, but I am not sure
   how to implement that yet.

# Design

Most of the design change I am proposing is motivated by 2 above - removing
tmp files entirely. All of the current data processing picocrypt does can be
done on each 1 MiB block at a time.

## reed_solomon.go

This file handles all of the reed solomon encryption/decryption work. In main
picocrypt, it is up to the high level program logic to always use 128/136 byte
blocks. In this refactor, I moved that responsibility to the RSEncoder and
RSDecoder classes. The caller can pass any number of bytes to RSEncoder.Encode,
and any extra bytes beyond the 128 byte chunks will be cached internally and
used in the next call.

The advantage of splitting the responsibility this way is that the higher level
encoder does not need to know details about how rs works - it just passes data
in, and gets data out. If we ever add changes later to how the rs encoding works
(like making the amount of redundancy configurable), only the code here will
need to change. The disadvantage is that there is more state to track, so it is
more complex. There is also the chance that the input data does not exactly
match 128 byte chunks, so a Flush call is necessary at the end to pad the last
chunk. Looking for feedback on thoughts about this tradeoff.

In main picocrypt, the files are decoded first by assuming the first 128 bytes
are correct, and if the auth tag does not match at the end, then run the entire
file again but force rs decoding. The reason for two passes is that decryption
is very slow, and usually not needed, so assume the best and go fast. This 
presents a problem for the no-tmp-file design, because I do not want to have to 
make two passes over the data. An alternative option is to read in the first
128 bytes and just re-encode them, seeing if that matches the current 136 bytes.
If they match, the 128 bytes are almost definitely the original bytes. If they
don't match, then run the expensive decoding and see if it is recoverable. This
is slower than skipping entirely, but much faster than forcing decoding on every
chunk.

TODO: give brief overview of each source file here

TODO: add tests

TODO: add documentation

TODO: add standard zip file support

TODO: add recursive zip file support

TODO: add file chunk support
