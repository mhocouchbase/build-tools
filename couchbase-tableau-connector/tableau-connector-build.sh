#!/bin/bash -ex

echo "Download dependent tools: maven, jdk and python"

#When set JDK_HOME to system installed, it didn't seem to work somehow.
#Download via cbdep so we have control over which version to use.
#Download maven (3.3.9+ should work)

JDK_VERSION=21.0.11+10
MAVEN_VERSION=3.9.11
PYTHON_VERSION=3.11.13

rm -rf deps && mkdir deps
rm -rf build
rm -rf dist && mkdir dist

pushd deps
cbdep install openjdk ${JDK_VERSION} -d .
cbdep install mvn ${MAVEN_VERSION} -d .
export JAVA_HOME=$(pwd)/openjdk-${JDK_VERSION}
export MVN_EXE=$(pwd)/mvn-${MAVEN_VERSION}/bin/mvn
export PATH=$(pwd)/mvn-${MAVEN_VERSION}/bin:${JAVA_HOME}/bin:$PATH
export KEYLOCKERTOOLS_DIR=$(pwd)/Keylockertools-linux-x64
# Keylockertools for digicert codesigning
curl -LfO https://latestbuilds.service.couchbase.com/buildteam/downloads/digicert/Keylockertools-linux-x64.tar.gz
tar xzf Keylockertools-linux-x64.tar.gz
printf "name = DigiCertOnePKCS11\nlibrary = ${KEYLOCKERTOOLS_DIR}/smpkcs11.so\nslotListIndex = 0\n" > ${KEYLOCKERTOOLS_DIR}/pkcs11properties.cfg
export PATH=${KEYLOCKERTOOLS_DIR}:${PATH}

# Also create a uv-managed python venv for tableau-connector-sdk
uv venv --python ${PYTHON_VERSION} --managed-python python-${PYTHON_VERSION}
export PY_EXE=$(pwd)/python-${PYTHON_VERSION}/bin/python3

popd

cp /tmp/CMakeLists.txt .

# Drive the production build through CMake. -DPRODUCTION_BUILD=ON makes CMake:
#   1. Stamp versions: connector -> ${VERSION}; JDBC driver and the connector's
#      couchbase-jdbc.version property -> ${VERSION}.tableau (the driver is built
#      from source as part of this build).
#   2. mvn install the artifacts, and
#   3. DigiCert code-sign the .taco(s).
# Which SDK flavor(s) get built is decided by the repo manifest's <annotation
# name="SDK"> (analytics | operational | both); the script does not pin a flavor.
#
# DIGICERT_PASSWORD is injected into the Jenkins job as an environment variable
# and read by CMake from the environment, so it never appears on a command line.
# The keystore / alias / timestamp authority use the CMake defaults
# (~/.digicert.jks, digicert, http://timestamp.digicert.com).
cmake -S . -B build \
    -DPRODUCTION_BUILD=ON \
    -DVERSION="${VERSION}" \
    -DBLD_NUM="${BLD_NUM}" \
    -DTACO_PYTHON="${PY_EXE}" \
    -DMAVEN_EXECUTABLE="${MVN_EXE}" \
    -DDIGICERT_PKCS11CFG=${KEYLOCKERTOOLS_DIR}/pkcs11properties.cfg \
    -DSM_KEYPAIR_ALIAS="key_1516743357"

cmake --build build

#Copy the built connector zip to dist for publishing. Exactly one flavor is
#built per job (selected by the repo manifest's SDK annotation), and each
#flavor names its dist zip <flavor>-tableau-connector-${VERSION}-${BLD_NUM}.zip
#(see build.taco.assembly.name), so match that and guard against an unexpected
#second flavor rather than silently shipping the wrong one.

shopt -s nullglob
zips=(cbas/cbas-jdbc-taco/*/target/*-tableau-connector-${VERSION}-${BLD_NUM}.zip)
shopt -u nullglob
if [ "${#zips[@]}" -ne 1 ]; then
    echo "ERROR: expected exactly one *-tableau-connector-${VERSION}-${BLD_NUM}.zip, found ${#zips[@]}: ${zips[*]}"
    echo "(this job must build a single SDK flavor; check the manifest SDK annotation)"
    exit 6
fi
cp -p "${zips[0]}" dist/
