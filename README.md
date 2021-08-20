# Demeuk
[![Documentation Status](https://readthedocs.org/projects/demeuk/badge/?version=latest)](https://demeuk.readthedocs.io/en/latest/?badge=latest) [![Tests](https://github.com/NetherlandsForensicInstitute/demeuk/actions/workflows/test.yml/badge.svg)](https://github.com/NetherlandsForensicInstitute/demeuk/actions/workflows/test.yml)

Demeuk is a simple tool to clean up corpora (like dictionaries) or any dataset
containing plain text strings. Example use cases are: cleaning up language dictionaries,
password sets (like for example RockYou) or any file containing plain text strings.

In those corpora you'll find encoding mistakes that have been made, or you want to remove some parts
of a line. Instead of creating a huge bash oneliner you can use demeuk to do all your cleaning.

Example usages:
 - Cutting
 - Length checking
 - Encoding fixing

Demeuk is written in Python3, this means of course that it is slower than for example cut.
However, Demeuk is written multithreaded and thus can use all your cores. Besides this Demeuk
can easily be extended to match your needs.

This application is part of the CERBERUS project that has received
funding from the European Union's Internal Security Fund - Police under
grant agreement No. 82201

Please read the docs for more information.

## Quick start
The recommended way to install demeuk is to install it in a virtual
environment.

```
# Create virtual environment
virtualenv <virtual environment name>
# Activate the virtual environment
source <virtual environment name>/bin/activate
pip3 install -r requirements.txt
```

Now you can run bin/demeuk.py:

Examples:
```
    demeuk -i inputfile.tmp -o outputfile.dict -l droppedfile.txt
    demeuk -i inputfile -o outputfile -j 24 -l logfile.log
    demeuk -i inputdir/*.txt -o outputfile.dict -l logfile.log
```

## Docs
The docs are available at: <http://demeuk.rtfd.io/>
