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

### 2. Configure you certificates

To communicate with the server, you need to download a TLS certificate, register api-key and download the corresponding private key file from your ArxanChain BaaS Chainconsole. Refer to [API cert management](http://www.arxanfintech.com/infocenter/html/chainconsole/manual.html#api) for more details.

After downloading the two files, use the following command to convert your private key file into PEM format.

```sh
$ openssl ec -in apikey.key -outform PEM -out apikey.key
```

Then copy (rename as follows) your TLS certificate and PEM private key file into your py-common installation path as follows. Please pay special attention to the absolute path of your certificate `./py_common-2.0-py2.7.egg/cryption/ecc/certs`, which will be used to create a client.

```
.
├── py_common-2.0-py2.7.egg
|   └── cryption
|       ├── ecc
|       |   └── certs
|       |       ├── tls
|       |       |   └── tls.cert
|       |       └── users
|       |           └── pWEzB4yMM1518346407
|       |               └── pWEzB4yMM1518346407.key
|       └── utils
|           └── utils.so
```

### Run unit test

The following command will run unit test.

```sh
$ pytest
```

