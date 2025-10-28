#!/bin/bash -ex
set -x
PRODUCT=$1
RELEASE=$2
VERSION=$3
BLD_NUM=$4

git clone ssh://git@github.com/couchbaselabs/agent-catalog.git
pushd agent-catalog
PYTHON_VERSION=$(grep "requires-python" pyproject.toml |awk -F '"|,' '{print $2}' |sed 's/[^0-9.]//g')
uv venv --python ${PYTHON_VERSION} ${WORKSPACE}/mypyenv
source ${WORKSPACE}/mypyenv/bin/activate
python -m ensurepip --upgrade --default-pip
pip install poetry
poetry lock
