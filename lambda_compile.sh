#!/bin/sh

yum install -y python310
python3.10 -m venv /tmp/venv
/tmp/venv/bin/pip install --upgrade pip setuptools
/tmp/venv/bin/pip install -e .
cp -r /tmp/venv/lib/python3.7/site-packages/. ./aws_lambda_libs
cp -r /tmp/venv/lib64/python3.7/site-packages/. ./aws_lambda_libs
