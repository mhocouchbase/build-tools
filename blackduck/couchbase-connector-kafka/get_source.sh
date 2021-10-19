#!/bin/bash -ex

PRODUCT=$1
RELEASE=$2
VERSION=$3
BLD_NUM=$4

git clone git://github.com/couchbase/kafka-connect-couchbase.git
pushd kafka-connect-couchbase
if git rev-parse --verify --quiet $VERSION >& /dev/null
then
    echo "Tag $VERSION exists, checking it out"
    git checkout $VERSION
else
    echo "No tag $VERSION, assuming master"
fi

# don't need to scan examples
rm -rf examples

mvn --batch-mode dependency:resolve
mvn --batch-mode -Dmaven.test.skip=true -Dmaven.javadoc.skip=true install

popd