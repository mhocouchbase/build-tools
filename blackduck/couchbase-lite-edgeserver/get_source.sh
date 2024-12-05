#!/bin/bash -ex
set -x
PRODUCT=$1
RELEASE=$2
VERSION=$3
BLD_NUM=$4

git clone ssh://git@github.com/couchbase/edge-server.git
pushd edge-server
git submodule update --init --recursive
if git rev-parse --verify --quiet ${VERSION} >& /dev/null
then
    echo "Tag ${VERSION} exists, checking it out"
    git checkout ${VERSION}
else
    echo "No tag ${VERSION}, assuming main/master"
fi
