#!/usr/bin/python

import setuptools
from dnstap_receiver import __version__

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()
    
KEYWORDS = ('dnstap receiver client json')

setuptools.setup(
    name="dnstap_receiver",
    version=__version__,
    author="Denis MACHARD",
    author_email="d.machard@gmail.com",
    description="Python Dnstap to JSON stream receiver",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/dmachard/dnstap_receiver",
    packages=['dnstap_receiver'],
    include_package_data=True,
    platforms='any',
    keywords=KEYWORDS,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries",
    ],
    entry_points={'console_scripts': ['dnstap_receiver = dnstap_receiver.receiver:start_receiver']},
    install_requires=[
        "dnslib",
        "protobuf3"
    ]
)
