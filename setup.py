import codecs

from setuptools import setup

from bin.demeuk import version

dependencies = [
    'docopt',
    'chardet',
    'nltk',
    'ftfy',
    'unidecode',
]

setup(
    name='demeuk',
    version=version,
    author='Netherlands Forensic Institute',
    author_email=codecs.encode('ubyzrfay@hfref.abercyl.tvguho.pbz', 'rot-13'),
    description='CLI tool to remove invalid chars from a corpus.',
    install_requires=dependencies,
    scripts=['bin/demeuk.py'],
)
