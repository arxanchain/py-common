# Status

[![Build Status](https://travis-ci.org/arxanchain/py-common.svg?branch=master)](https://travis-ci.org/arxanchain/py-common)

## py-common

py-common is an implementation of the sdk-go-common in Python.

## Contributions

Welcome for any kind of contributions, such as open issues, fix bugs and improve documentation.

## Install

**Note:** Currently we only support **Linux 64bit** environment by default, if you are not aware of what environment you are using, run the following command to check out.

```python
>>> import platform
>>> print platform.system() # os
>>> print platform.architecture() # architecture
```

If you want to run py-common in your operating system, you need to use sdk-go-common tools to generate executables and replace them into directory `py-common/cryption/utils`. For more details please refer to [sdk-go-common](https://github.com/arxanchain/sdk-go-common/tree/master/crypto/tools/README.md)

The following command will install py-common in a virtual environment.

```sh

$ virtualenv venv  # create a virtual env
$ source venv/bin/activate  # activate virtual env

$ python setup.py install # install py-common

$ deactivate # deactivate virtual env
```

