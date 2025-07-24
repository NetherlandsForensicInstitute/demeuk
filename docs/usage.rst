Usage
=====
This document describes how to usage demeuk.

Please read ::ref:`Install` 

Basic usage
-----------
An example usage for demeuk is to clean up a password list

Download a list, like for example RockYou. Then run the following command:

.. code-block:: none

    $ demeuk.py -i <input file> -o <output file> -l <log file> 
    -c -j 8 --leak --remove-email

So what do all the parameters do? The -i selects the input file. The -o specifies
the output file. The -l will specify the log file, by default the log file will only
contain information on lines containing invalid characters. For example this
can be lines where demeuk was not able to detect the encoding correctly. If you want
detailed logging, also include the --verbose and --debug option. The -c
specifies that there will be cut based on the first ':' found in a string. The -j
indicates that we will be using multithreading and we'll be creating 8 threads.
Demeuk has been tested with as many as 48 cores and all cores will be fully used,
if IO is not a problem (for example on a fast SSD setup).

The --leak option indicates the following modules: 
--mojibake, --encode, --newline, --check-controlchar. 
--mojibake will try to detect and fix encoding issues known as mojibakes. Example of a Mojibake is
SmˆrgÂs (Smörgås). This is a very common encoding issue. --encode will enable the encoding detection of
demeuk. --newline will remove newlines from lines. --check-controlchar will drop lines containg control-chars.

This set of options was the default for demeuk version 3 and lower.

The --remove-email option will remove simple email addresses from a line. It is useful when a dataset
contained line like  <something>:<email>:password.

Some datasets contain encoded strings like hex strings (HEX[] format). Those can be 
decoded using the following example:

.. code-block:: none

    $ cat inputfile | demeuk.py -j all --leak | sort -u

When --input or --output is not specified, demeuk will use stdin and stdout.
This allows for easy combining with other tools.

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

Have totally no idea and just what a leak to be fully demeaked? Use the following command:

.. code-block:: none

    $ demeuk.py -i <input file> -o <output file> -l <log file> -j all --leak-full

Standard Options
----------------
i input
~~~~~~~
The input option can be used to select the input file. This can also be a glob
pattern. For example: "testdir/\*.txt".

When not specified it will use stdin as input.

o output
~~~~~~~~
The output option can be used to select the output file.

When not specified it will use stdout as output.

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

punctuation
~~~~~~~~~~~
Use to set the punctuation that is use by options. For example used by the --remove-punctuation 
option.

Defaults to all ascci punctuation:
! "#$%&'()*+,-./:;<=>?@[\]^_`{|}~

verbose
~~~~~~~
Use the verbose option to log lines which are causing some error. For example
lines that are too long or lines that are not able to be decoded.

debug
~~~~~
Use the debug option to log all the changes made to any line. Note that this will impact
the performance of demeuk significantly. Also this will create a large log file.

progress
~~~~~~~~
Use the progress option to enable the progressbar. The progressbar will be displayed for
both the chunkify process as well as the demeuking process.

Progress can only be used when the input is a file. It can not be used when the input is
stdin.

n limit
~~~~~~~
Limit the number of lines that will be processed. Useful when working with a large dataset
and when you want to debug results quickly. Note that the limit parameter is set per thread. This means
that if you set the limit to 5 and create 2 threads, 10 lines will be processed. This is not
entirely true, if the input file is too small (minimal chunk size) to spawn two threads the
limit will only apply to the only thread that could be spawned.

n skip
~~~~~~
Skip n lines starting from the start of the file.


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
~~~~~~~~~~~~
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

check-controlchar
~~~~~~~~~~~~~~~~~
Enable this option to drop lines containg control-chars. Mostly lines containing
control-chars are invalid lines, for example lines which are decoded incorrectly.

check-email
~~~~~~~~~~~
Check if a line contains an e-mail address. If so, it drops. It should be noted that this
is a every simple regex. Also it is the same regex used for remove-email.

check-hash
~~~~~~~~~~
Checks if a line is an hash. If so the line is dropped. The regex used are quite
simple. One regex check if a line, from start to finish, contains a-f and 0-9's only.
The other checks if the line contains a structure which looks like linux hash. Something
like

$1$fjdfh$qwertyuiopjfsdf

check-mac-address
~~~~~~~~~~~~~~~~~
Checks if a line is a mac address. If so the line is dropped.
The line has to be a mac-address from start to finish.

The following line will be dropped:

00:11:22:33:44:55

but a line like:

Dummy:00:11:22:33:44:55

will not be dropped

check-uuid
~~~~~~~~~~
Checks if a line is an UUID. If this line is a UUID, it will be dropped.
The line has to be an UUID from start to finish.

Example

d4662e44-00f1-4ef6-857e-76e3c61604cd

will be dropped

Example

dummy-d4662e44-00f1-4ef6-857e-76e3c61604cd

will not be dropped

check-non-ascii
~~~~~~~~~~~~~~~
Checks if a line contains non-ascii chars. It does this by using the 'ascii' encoding
builtin Python. If the line does not encode correctly the line is dropped.

check-replacement-character
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Checks if a line contains the replacement character. This is the '�' Symbol. Mostly
when a line contains this char this is an indication that some decoding error happend.
The problem is that with this char all information is lost about the original character.
So it is very complicated to repair this encoding error. With this option you can drop
lines contain this char.

check-starting-with
~~~~~~~~~~~~~~~~~~~
Checks if a line starts with the argument of check-starting-with. If the line starts
with this, the line will be dropped. The string to check can be multiple strings. multiple
values are comma-seperated. Example: #,// would skip lines starting with '#' and with 
'//'.

If you enabled the '--tab' option and you want to drop lines starting with a tab, add 
':' to the list of strings to check. '--check starting-with :'. When using --tab tab
characters are transfered to ':'.

check-ending-with
~~~~~~~~~~~~~~~~~
Checks if a line ends with the argument of check-ending-with. If the line ends
with this, the line will be dropped. The string to check can be multiple strings. Multiple
values are comma-seperated. Example: #,// would skip lines ending with '#' and with 
'//'.

If you enabled the '--tab' option and you want to drop lines ending with a tab, add
':' to the list of strings to check. '--check ending-with :'. When using --tab tab
characters are transfered to ':'.

check-contains
~~~~~~~~~~~~~~
Checks if a line contains the argument of check-contains. If the line contains this,
the line will be dropped. The string to check can be multiple strings. Multiple values
are comma-separated. Example: #,// would skip lines containing '#' and '//'.

If you enabled the '--tab' option and you want to drop lines ending with a tab, add
':' to the list of strings to check. '--check ending-with :'. When using --tab tab
characters are transfered to ':'.

check-empty-line
~~~~~~~~~~~~~~~~
Checks if a line only contains whitespace characters or is empty. If this is true,
the line will be dropped.

check-regex
~~~~~~~~~~~
Checks if a line matches a list of regexes. Regexes are comma-seperated. If the line does not
matches all of the regexes, the line will be dropped.
Example: --check-regex '[a-z],[0-9]' will drop lines
that do not atleast contain one lowercase char and one number.

Want to remove a line that does not contain an underscore?
--check-regex '^[^_]+$'

Want to remove a line that start with a specific strings?
--check-regex '^[^this]' will remove lines starting with 'this'


check-min-digits
~~~~~~~~~~~~~~~~
Checks if a line contains a minimum number of digit characters. If the line does not contain
enough digit characters, the line will be dropped. Apart from the ASCII digits 0-9, it includes
other unicode digits as well. It follows the Python definition of a digit,
see https://docs.python.org/3/library/stdtypes.html#str.isdigit

check-max-digits
~~~~~~~~~~~~~~~~
Checks if a line contains a maximum number of digit characters. If the line contains too many
digit characters, the line will be dropped. Apart from the ASCII digits 0-9, it includes
other unicode digits as well. It follows the Python definition of a digit,
see https://docs.python.org/3/library/stdtypes.html#str.isdigit

check-min-uppercase
~~~~~~~~~~~~~~~~~~~
Checks if a line contains a minimum number of uppercase characters. If the line does not contain
enough uppercase characters, the line will be dropped. Apart from the ASCII uppercase characters A-Z, it includes
other unicode uppercase characters as well. It follows the Python definition of an uppercase character,
see https://docs.python.org/3/library/stdtypes.html#str.isupper

check-max-uppercase
~~~~~~~~~~~~~~~~~~~
Checks if a line contains a maximum number of uppercase characters. If the line contains too many
uppercase characters, the line will be dropped. Apart from the ASCII uppercase characters A-Z, it includes
other unicode uppercase characters as well. It follows the Python definition of an uppercase character,
see https://docs.python.org/3/library/stdtypes.html#str.isupper

check-min-specials
~~~~~~~~~~~~~~~~~~
Checks if a line contains a minimum number of special characters. If the line does not contain
enough special characters, the line will be dropped. A special character is defined as a character
which is both not a whitespace and not an alphanumeric character. Apart from the ASCII special characters,
it includes other unicode special characters as well. The definition of a whitespace and alphanumeric
character follows those of Python, see https://docs.python.org/3/library/stdtypes.html#str.isspace
and https://docs.python.org/3/library/stdtypes.html#str.isalnum

check-max-specials
~~~~~~~~~~~~~~~~~~
Checks if a line contains a maximum number of special characters. If the line contains too many
special characters, the line will be dropped. A special character is defined as a character
which is both not a whitespace and not an alphanumeric character. Apart from the ASCII special characters,
it includes other unicode special characters as well. The definition of a whitespace and alphanumeric
character follows those of Python, see https://docs.python.org/3/library/stdtypes.html#str.isspace
and https://docs.python.org/3/library/stdtypes.html#str.isalnum

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

transliterate
~~~~~~~~~~~~~
Replaces Cyrillic characters with their Latin equivalents. For example, жута becomes Žuta. To take this even further,
combine it with --non-ascii to convert this to zuta.

The follow languages are supported: ka, sr, l1, ru, mn, uk, mk, el, hy and bg

--transliterate ru

Check https://pypi.org/project/transliterate/ for more details.

lowercase
~~~~~~~~~~
Replace lines like 'Test Test Test' to 'test test test'. Basically lowercasing all
words in a line.

title-case
~~~~~~~~~~
Replace lines like 'test test test' to 'Test Test Test'. Basically uppercasing all
words in a line.

mojibake
~~~~~~~~
Use this option to enable trying encoding issues known as mojibakes. Example of a Mojibake is
SmˆrgÂs (Smörgås). This is a very common encoding issue. This option will try to detect
and fix this issue.

encode
~~~~~~
Use this option to enable the encoding guessing of demeuk. This force to decode
using the --input-encoding option. Only use this if you are 100% of the input encoding.

tab
~~~~~~
If you enable this, demeuk will replace tab characters with ':'. 
This is useful when cleaning up data from collection leaks. They might
contain tab characters and ':' as seperator in the same file.

newline
~~~~~~~
Enable this option to remove newlines from lines. This can be extra important 
when using --html or --hex, the decoded lines may contain newline characters.
To remove those newline characters, enable this option.


trim
~~~~
Enable this to let demeuk trim lines. Demuk will removes remove sequences which represent 
newline characters from beginning and of end of input entry. For example the Ascii sequence '\n' or
Html sequence '<br />'. But in case this sequences are part of a password this
option allows to disable this option.



Remove modules
--------------
remove-strip-punctuation
~~~~~~~~~~~~~~~~~~~~~~~~
Remove starting and trailing punctuation. A line like: test- will be converted to
test. This option is useful for language corpora.

remove-punctuation
~~~~~~~~~~~~~~~~~~
Remove any punctuation from a line. A line like 'test - hi' will be converted to 'testhi'.
What punctuation will be removed can be specified with the '--punctuation' option.

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

add-first-upper
~~~~~~~~~
When working with language dictionaries it can be handy to keep all-upper and all-lower
letters inside your corpora. For example the entry 'AMSTERDAM' or 'cookies' are likely
to be used in this form. But still you probably want 'Amsterdam' and 'Cookies' in your
corpora. This option keeps both the original format and the capitalized part in the corpora.

add-title-case
~~~~~~~~~
When working with language dictionaries it can be handy to keep all-lower letters inside
your corpora. For example the entry 'my name' is likely to be used in this form. But still
you probably want 'My Name' in your corpora. This option keeps both the original format and
the title case format in the corpora.

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

add-without-punctuation
~~~~~~~~~~~~~~~~~~~~~~~
If a line contains punctuations, a variant will be added without the punctuations.
Example a line like: 'test-123' will be kept, plus 'test123' will be added.
Which punctuation will be removed can be specified with the --punctuation option.


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

leak
~~~~
The leak option will enable the following modules:
    
 - mojibake
 - encode
 - newline
 - check-controlchar


leak-full
~~~~~~~~~
The leak-full option will enable the following modules:

 - mojibake
 - encode
 - newline
 - check-controlchar
 - hex
 - html
 - html-named
 - check-email
 - check-hash
 - check-mac-address
 - check-uuid
 - check-replacement-character
 - check-empty-line
