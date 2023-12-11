Design
======

This document will describe how the internal of demeuk are designed. It gives
some insight on how the application works. Mostly it is useful in case you
are working with a bug or don't understand why something is happening and it
is a must read for anyone adding features to demeuk.

Threading
---------
In cause of an input file, the file is 'chunked' by the main processes. It will split
the input files in chunks. It does so by reading the file per 1 KB. After reading 1 KB
it will search for the next newline after the 1 KB. It will then read again 1 KB and 
search for the first new line after that. This will continue until the end of the file.

The size of 1 KB is used to reduce memory load and was found to be a solid number for
good performance.

When using stdin, the input is not chunked. This is because stdin is a stream and
thus we can not seek to a specific offset. So the main thread will read the input
per 1 KB and search for the first newline after that.

Next a thread will open the input file and seek to the start offset. It will read
the remaining byte to the end offset and starts processing the lines.

Will processing the input file, the thread will create a temp file inside the folder
'demeuk_tmp' inside the current working directory. Inside this temp file intermediate
results will be written to reduce memory usages. Note: many thread will cause a significant
IO storm. If you see a lot of IO wait, reduce the amount of threads or replace you disks
with faster disks.

Once all threads are done, the main thread will combine all of the results in the
temp folder. You should note that the order inside the final output will be completely
un ordered and thus if you want to have a sorted list you need to sort it yourself.

Encoding detection
------------------
So, a thread has opened a file, it will start reading it using the splitlines() python
function. This means the line will be splitted on: line feed, carriage return,
LF + CR, formfeeds, file separator, etc. See https://docs.python.org/3/library/stdtypes.html
for more information.

Next, when '--tab' is enabled all tabs will be converted to ':' greedy. This is to have
a single cut/splitting char. This is done on binary level.

Next, we arrive at one of the most important things of this application. The encoding detecting
enable this with '--encode'. Some dataset are a combination of different sources. This means
EVERY line can have a different encoding. People or applications tend to make a lot
of errors in encoding, as does this application. Demeuk tries its best to detect
and correct as much as possible, but there will for sure be some weird case where it fails
to do so. By default the application will try to decode the data using UTF-8.

So we start by checking if we have a default encoding to try. This is either
UTF-8 or supplied by the user. If the line decodes and there does not appear to be
control character inside the line we can assume that the detection went correctly.
Also, if you supply a list of input encodings. First put multibyte encodings first.
Because single byte encodings will cause false positives.

If that fails we run the detect function of the chardet library. Note: first the 
cchardet library was implemented, but this library resulted in too many wrongly
encoded lines. Inside the tests of demeuk there are lot of edge cases which were
found and corrected. So if you change something in the encoding detection
please run the tests to verify that you have not broken something.

If it managed detect any encoding, it will try to decode this line. If no unicode
error happens we assume that we got some result.

Next we try to fix mojibakes, for this enable the --mojibake option
basically, we might have decoded the string incorrectly
and now correct some of the common errors. For this we use the FTFY library.

Modules
-------
After a line has been decoded correctly demeuk will start to run all the modules.
Demeuk consist of 4 different type of modules.

- Clean modules. Those modules modify something in a line. For example replace tab
  character with ':'. The commandline parameters will have the name of the module 
  without a prefix.
- Add modules. Those modules will modify something in a line, but keep the original
  line aswell. For example, add a lower case variant of a line. These modules will
  have the commandline parameters start with 'add-' prefix.
- Check modules. Those modules will check if a line passes some test. For example
  a minimal length check. The commandline parameters start with the 'check-' prefix.
  If a line fails the check, the line is dropped.
- Remove modules. Those modules will remove specific parts of a line and does this
  in place. For example punctuation needs to be removed, those modules will be used.
  The commandline parameters will start with the 'remove-' prefix.

The name that a module has on the commandline will mean that the function inside the
source code must also has the exact same name. Only clean module will start with the
'clean\_' prefix to prevent name clashes with default functions.

Note that when any add option is used, any other modules (like clean, check, remove
AND even add) will be ran on the modified line again. This might result in creating
an loop if it keeps creating new lines. So be careful with using those options.

For now there is no specific order in which the module type will run. Apart from
the add modules, which will always run last. If someone find a specific use case
for which the order needs to be configured; please submit a bug.

Another note on the add modules and threading. Lines are dedicated to different
threads based on a configured chunk size. When additional lines are added, all
other modules will run again on the line. The thread that created the new line
will also run those modules again. Meaning that if one thread creates a lot of
different new lines that thread might be busier then other threads. But because
the chunksize is quite small, this will probably not be an issue. If this is an
issue for someone please submit a bug.