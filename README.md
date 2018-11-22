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

**Note:** Before using the py-common in your application, you need to make the following preparations:

### 1.Configure your encryption and signing libraries

1. Build dynamic link library with sdk-go-common encryption tools(Ubuntu users can go through this step because library file is installed by default). To build this library, you need to install **golang** and download **sdk-go-common**. For more details please refer to [sdk-go-common](https://github.com/arxanchain/sdk-go-common/tree/master/crypto/tools/README.md).

2. Copy the library file **utils.so** into your py-common installation path `cryption/utils`.

If you have no idea where your py-common is installed, use the following command to check it out (you need to leave the py-common code repo before running this command).

```sh
$ python -c 'import imp;print imp.find_module("cryption")[1]'
/usr/local/lib/python2.7/site-packages/py_common-2.0-py2.7.egg/cryption
```

In this case, you should create directory `/usr/local/lib/python2.7/site-packages/py_common-2.0-py2.7.egg/cryption/utils/`, and copy the file into this path.

```
.
├── py_common-2.0-py2.7.egg
|   └── cryption
|       └── utils
|           └── utils.so
```

### 2. Configure your certificates

To communicate with the server through HTTPS protocol, you need to download a CA certificate, register api-key and download the corresponding zip-file including client private key and cert from your ArxanChain BaaS Chainconsole. Refer to [API cert management](http://chain.arxanfintech.com/infocenter/html/chainconsole/manual.html#api) for more details.

Finaly, you will get three files as following. Please pay special attention to the absolute path which will be used to create a client.

```
.
├── your path
|   └── rootca.crt
|   └── api-key.key
|   └── api-key.pem
```

### Run unit test

The following command will run unit test.

```sh
$ pytest
```

