#!/bin/bash -ex

MAVEN_VERSION=3.9.5
cbdep install -d ${WORKSPACE}/extra mvn ${MAVEN_VERSION}
mv ${WORKSPACE}/extra/mvn-${MAVEN_VERSION} ${WORKSPACE}/extra/mvn
export PATH=${WORKSPACE}/extra/mvn/bin:$PATH

pushd cbtaco
mvn wrapper:wrapper

./mvnw dependency:copy-dependencies \
    -DincludeScope=runtime
mv cbas/cbas-jdbc-taco/target/dependency .
cd dependency
for file in $(ls *.jar); do
  jar -xf $file
done
popd
