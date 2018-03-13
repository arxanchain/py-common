# Status

[![Build Status](https://travis-ci.org/arxanchain/py-common.svg?branch=master)](https://travis-ci.org/arxanchain/py-common)

## py-common

py-common is an implementation of the sdk-go-common in Python.

## Contributions

Welcome for any kind of contributions, such as open issues, fix bugs and improve documentation.

## Install

The following command will install py-common in your python environment.

```sh

$ python setup.py install # install py-common
```

## Usage

**Note:** Before using the py-common in your operating system, you need to make a two-step preparation:

### 1.Configure your cryption tool and signature tool

1. Build executables with sdk-go-common cryption tools. To build these tools, you may need to install **golang** package **sdk-go-common**. For more details please refer to [sdk-go-common](https://github.com/arxanchain/sdk-go-common/tree/master/crypto/tools/README.md)

2. Copy executables **crypto-util** and **sign-util** into your py-common installation path `cryption/utils`

If you have no idea where your py-common is installed, use the following command to check out(you need to jump out of your git clone directory before running this command).

```sh
$ python -c 'import imp;print imp.find_module("cryption")[1]'
/usr/local/lib/python2.7/site-packages/py_common-1.5.0-py2.7.egg/cryption
```

In this case, you should copy executables into path `/usr/local/lib/python2.7/site-packages/py_common-1.5.0-py2.7.egg/cryption/utils/`

### 2. Configure you certificates

To communicate with server, you need to download TLS certificate, register api-key and download the corresponding private key file from your chainconsole, if you have no idea how to start, please refer to [API cert management](http://www.arxanfintech.com/infocenter/html/chainconsole/manual.html#api)

After downloaded the two files, use the following command to convert your private key file into PEM format

```sh
$ openssl ec -in apikey.key -outform PEM -out apikey.key
```

Then copy(rename if neccessary) your TLS certificate and PEM private key file into your py-common installation path as the following

```
.
├── py_common-1.5.0-py2.7.egg
|   └── cryption
|       ├── ecc
|       |   └── certs
|       |       ├── tls
|       |       |   └── tls.cert
|       |       └── users
|       |           └── pWEzB4yMM1518346407
|       |               └── pWEzB4yMM1518346407.key
|       └── utils
|           ├── sign-util
|           └── crypto-util
```

### Run unit test

The following command will run unit test

```sh
$ pytest
```

