Usage
=====
This document describes how to usage demeuk.

Please read ::ref:`Install` 

Basic usage
-----------
An example usage for demeuk is to clean up a password list

Download a list, like for example RockYou. The first step you have to document
is combine the datafiles into one single file. Using default Linux tooling for this
works very well. Next you'll run demeuk on the data to clean it up.

.. code-block:: none

    $ demeuk.py -i <input file> -o <output file> -l <log file> -c -j 8 -remove-email

So what do all the parameters do? The -i selects the input file. The -o specifies
the output file. The -l will specify the log file, by default the log file will only
contain information on lines containing invalid characters. For example this
can be lines where demeuk was not able to detect the encoding correctly. If you want
detailed logging, also include the -v option (verbose logging). The -c
specifies that there will be cut based on the first ':' found in a string. The -j
indicates that we will be using multithreading and we'll be creating 8 threads.
Demeuk has been tested with as many as 48 cores and all cores will be fully used,
if IO is not a problem (for example on a fast SSD setup). The --remove-email option
will remove simple email addresses from a line. It is useful when a dataset
contained line like  <something>:<email>:password.

Some datasets contain encoded strings like hex strings (HEX[] format). Those can be 
decoded using the following example:

.. code-block:: none

    $ demeuk.py -i <input file> -o <output file> -l <log file> -j all --hex --html

The '-j all' option allows demeuk to use all CPU cores in the system. --hex will unhex
hex strings. --html will un-htlm htlm escaped passwords.

For additional parsing, demeuk can select based on length of password and even do cutting
of the correct field in case of field separated file.

Take for example the entry: testuser:some address:birthday:password

To take the password using demeuk run the following command:

.. code-block:: none

    $ demeuk.py -i <input file> -o <output file> -c -f4

The -c option tells demeuk to cut, and -f4 tell demeuk to select the 4-th field.

Standard Options
-------------
i input
~~~~~~~
The input option can be used to select the input file.

o output
~~~~~~~~
The output option can be used to select the output file.

l log
~~~~~~
The log option can be used to select to which file a lines needs to be written
that are invalid for some reason. There can be multiple reasons, length, encoding
and a lot more reason. If the verbose flag is set, this file will also contain
any changes, addition or removals that have been made on the line.

j threads
~~~~~~~~~
The threads option can be used to speed up the process of demeuking. Of course
this option needs to be a number. Do not use more threads then CPU core on your
machine. Use the string 'all' to specify to use all cores. Example: -j all

input-encoding
~~~~~~~~~~~~~~
By default demeuk will try to detect the encoding per line. If you already know
the input encoding you can specify it using this option. Using this option can speed 
up the demeuking process significantly. Note: if demeuk fails to decode the line 
using this encoding, it will still perform the default encoding detection. Thus 
specifying a not installed encoding will not result in an error.

output-encoding
~~~~~~~~~~~~~~~
Probably you do not want to change this option, it defaults to 'en_US.UTF-8'.
But in case you want to change the output encoding, use this option.
Note, this will change the internal python unicode encoding.

verbose
~~~~~~~
Use the verbose option to log all the changes made to any line. Note that this will impact
the performance of demeuk significantly. Also this will create a large log file.

n limit
~~~~~~~
Limit the number of lines that will be processed. Useful when working with a large dataset
and when you want to debug results quickly. Note that the limit parameter is set per thread. This means
that if you set the limit to 5 and create 2 threads, 10 lines will be processed. This is not
entirely true, if the input file is too small (minimal chunk size) to spawn two threads the
limit will only apply to the only thread that could be spawned.


Separating options
------------------
c cut
~~~~~
Will perform a cut on the line using the delimiter that can be specified.
By default it will work with everything AFTER the first delimiter. If the delimiter
is present multiple times, the cut will only be performed on the first delimiter.
This is in case passwords do contain the delimiter as a character in the password.
For example to correctly get the password from the line: 
<username>:mypassword:is:very:interesting.

f cut-fields
~~~~~~~~~~~
When specifying the --cut command, the cut-fields command can be used to specify
which fields needs to be cut. The same syntax as the -f command in the cut binary
can be used. This means:

N N'th field, N- from N-th field to end line, N-M, from N-th field to M-th field. 
-M from start to M-th field.

So examples -f 1-2, will cut field 1 till 2. -f 5 will cut field 5.

cut-before
~~~~~~~~~~
The cut before option can be used to work with everything before the first
delimiter. Basically reverting the default behavior.

d delimiter
~~~~~~~~~~~
Use the delimiter option to cut on a different delimiter. Like cutting on '/'.
Default to ':', multiple delimiters can be specified using a ','. If it is needed
to split on a comma, make the first delimiter a ','. If you need a comma and multiple 
delimiters specify the delimiters using ';'. Example: ',;:' would split on ',' and ':'.
The order in which they appear matters, the first delimiter will be tested first.


Check modules
-------------
check-min-length
~~~~~~~~~~~~~~~~
Returns only lines that have a specific minimum amount of unicode chars. This
is different from the hashcat-utils len.bin, because len.bin works with byte
length. The min-length option works with unicode length.

check-max-length
~~~~~~~~~~~~~~~~
Returns only lines that do not have a specific amount of unicode chars. This
is different from the hashcat-utils len.bin, because len.bin works with byte
length. The max-length option works with unicode length.

check-case
~~~~~~~~~~
Check case is a very nifty trick to verify a line is valid printable chars.
It will perform a .lower() and .upper() on the line and verify that all characters
changed. If some of the char did not change it must mean that there are
some punctuation chars inside the line. This option is mostly useful for cleaning
up language corpora.

A side effect is that also number will be removed. The check case will ignore
some punctuation by default. It will ignore: " ", "'" and "-".

no-check-controlchar
~~~~~~~~~~~~~~~~~~~~
Disable to option to not drop lines containing control chars. This can be handy to speed
up demeuk if you are 100% sure about the input encoding.

check-email
~~~~~~~~~~~
Check if a line contains an e-mail address. If so, it drops. It should be noted that this
is a every simple regex. Also it is the same regex used for remove-email.

check-hash
~~~~~~~~~~
Checks if a line contains an hash. If so the line is dropped. The regex used are quite
simple. One regex check if a line, from start to finish, contains a-f and 0-9's only.
The other checks if the line contains a structure which looks like linux hash. Something
like

$1$fjdfh$qwertyuiopjfsdf

check-non-ascii
~~~~~~~~~~~~~~~
Checks if a line contains non-ascii chars. It does this by using the 'ascii' encoding
builtin Python. If the line does not encode correctly the line is dropped.

Modify modules
--------------
hex
~~~
Hashcat convert non-ascii char to hex strings starting with $HEX, but when using
corpora for a different attack, the corpora might need to be translated to a different
encoding. Thus it is beter to keep one standard and convert HEX strings to plain unicode.

The hex option does this, if a line contains $HEX[], the data between [] will be converted
back to a proper byte string and finally be decoded using demeuks decode algorithm.

Small note, if a real passwords contain $HEX[], this will also be converted.

html
~~~~
Some datasets might contain strings containing html encoded passwords. This can happen
because of a implementation of a hash algorithm that encodes passwords submitted by a user
in html encoding to support non-ascii characters.

A string like: &#304;STANBUL will be converted to İSTANBUL. Note, if an password would 
really contain &#304; those entries would also be converted. Thus might invalidate some
passwords.

This subcommand will only match entries starting with &# followed by alphanumeric and end with
a ';'. If you want entries like &gt; to be removed, use the html-named option.

html-named
~~~~~~~~~~
Html-named option will replace entries like &gt; with '>' and &alpha; with the alpha letter. Some of those
entries look quite like password entries. Thus use this option with care.

umlaut
~~~~~~
In some spellings website the umlaut is not used correct. For example they are encoded as
the characters a". This should of course be an a with an umlaut.

non-ascii
~~~~~~~~~
Replaces Unicode chars to 7-bit Ascii replacement. For this the following lib is used:
https://pypi.org/project/Unidecode/

For example a line like 'kožušček' is replaced to kozuscek.

no-mojibake
~~~~~~~~~~~
Use this option to disable the default behavior of trying to fix encoding issues.

no-encode
~~~~~~~~~
Use this option to disable the encoding guessing of demeuk. This force to decode
using the --input-encoding option. Only use this if you are 100% of the input encoding.

no-tab
~~~~~~
Defaulty demeuk will replace tab characters with ':' to make splitting easier. But in case
tabs can be part of a password this option allows to disable this option.



Remove modules
--------------
remove-punctuation
~~~~~~~~~~~~~~~~~~
Remove start and end punctuation. A line like: test- will be converted to
test. This option is useful for language corpora. Currently it will only strip
' ' and '-'.

remove-email
~~~~~~~~~~~~
The email option will catch lines containing email addresses. like:
12234:test@example.com:password. Not that it is a very simple email filter and
many lines will still get through. Especially lines with long subdomains.
This option is still very useful for data containing lots of datastructures.


Add modules
-----------
add-lower
~~~~~~~~~
When working with language dictionaries it can be handy to keep capitalize
letters inside your corpora. For example the entry 'Amsterdam' or 'OpenOffice' are likely
to be used in this form. But still you probably want 'amsterdam' and 'openoffice' in your
corpora. This option keeps both the original format and the lowered part in the corpora.

add-latin-ligatures
~~~~~~~~~~~~~~~~~~~
In some encoding some characters can be written as one character while they can
also be written as two separate chars. Examples of those are ij and ae. This option
check if there are any, if there are it will convert the doubled character and
add un-double it, but keeping the original in the corpora as well.

So in case: cĳfer is present, both cĳfer and cijfer will be added.

add-umlaut
~~~~~~~~~~
In some spellings website the umlaut is not used correct. For example the characters a" are
in those sites. This should of course be an a with an umlaut.

add-split
~~~~~~~~~
In some language dictionaries some words are coupled that might be interesting to also
add uncoupled.

Example: 3D-printer, add split will split the word and add: 3D, printer and 3D-printer
to the corpora. Note: Add-split will not perform a length check that was specified
using the --min-length option. It only checks if the length of a split part is longer then
1 unicode character.


Macro modules
-------------
g googlengram
~~~~~~~~~~~~~
In case you are working with the googlengram's, this option is a macro for:

 - Don't remove control characters or tabs
 - Don't detect mojibakes
 - Do detect encoding
 - Strip ngram tagging

When using --googlengram, don't using any other options.

Basically it will strip the tags like: _NOUN_ or _ADJ
