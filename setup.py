#!/usr/bin/env python

from setuptools import setup, find_packages
import io

with open('./requirements.txt') as reqs_txt:
    requirements = [line for line in reqs_txt]

setup(
    name='py-common',
    version='1.5.0',
    description="Python common SDKs for Arxanchain.",
    long_description=io.open('README.md', encoding='utf-8').read(),
    url='https://github.com/arxanchain/py-common/',
    download_url='https://github.com/arxanchain/py-common/',
    packages=find_packages(),
    platforms='any',
    install_requires=requirements,
    include_package_data=True,
    zip_safe=False,
)
