#!/usr/bin/env python

from setuptools import setup, find_packages
import io

with open('./requirements.txt') as reqs_txt:
    requirements = [line for line in reqs_txt]

setup(
    name='py-common',
    version='2.0',
    description="Python common SDKs for Arxanchain.",
    long_description=io.open('README.md', encoding='utf-8').read(),
    url='https://github.com/arxanchain/py-common/',
    download_url='https://github.com/arxanchain/py-common/',
    packages=find_packages(),
    platforms='any',
    install_requires=requirements,
    dependency_links=[
        "git+git@github.com:gabrielfalcao/HTTPretty.git#egg=httpretty"
    ],
    package_data={
        "cryption": ["cryption/ecc/certs/tls/tls.cert",
            "cryption/ecc/certs/users/pWEzB4yMM1518346407/pWEzB4yMM1518346407.key"
            "cryption/utils/utils.so",
            "cryption/utils/utils.h"
            ]
        },
    zip_safe=False,
    include_package_data=True,
)
