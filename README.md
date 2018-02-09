# Status

[![Build Status](https://travis-ci.org/arxanchain/py-common.svg?branch=master)](https://travis-ci.org/arxanchain/py-common)

## py-common

py-common is an implementation of the sdk-go-common in Python.

## Contributions

Welcome for any kind of contributions, such as open issues, fix bugs and improve documentation.

## Install

The following command will install py-common in a virtual environment.

```sh

$ virtualenv venv  # create a virtual env
$ source venv/bin/activate  # activate virtual env

$ python setup.py install # install py-common

$ deactivate # deactivate virtual env
```

## Usage

**Note:** Before using the py-common in your operating system, you need to make some preparation which goes in two steps:

1. Build executables with sdk-go-common cryption tools. For more details please refer to [sdk-go-common](https://github.com/arxanchain/sdk-go-common/tree/master/crypto/tools/README.md)

2. Copy executables **crypto-util** and **sign-util** into your py-common installation path `py-common/cryption/utils`.

If you have no idea where your py-common is installed, user the following command to check out.

```sh
$ python -c 'help("cryption")'
Help on package cryption:

NAME
    cryption

FILE
    /usr/local/py-common-env/py-common/cryption/__init__.py

PACKAGE CONTENTS
    crypto

(END)
```
