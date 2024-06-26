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

TODO: give brief overview of each source file here

TODO: add tests

TODO: add documentation

TODO: add standard zip file support

TODO: add recursive zip file support

TODO: add file chunk support
