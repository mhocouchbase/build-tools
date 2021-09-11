#!/bin/bash -e

this_dir=$(dirname $0)
pushd ${this_dir}

STAGING=$1
BETA=$2

# Version, release and distro codenames are passed in as environment variables by go.sh
if [ -e "$DISTRO_CODENAMES" -o -e "$VERSION" -o -e "$RELEASE" ]
then
  echo "Env vars not specified, this script should be triggered by go.sh"
  exit 1
fi

if [[ "${STAGING}" == "yes" ]]; then
    STAGE_EXT="-staging"
else
    STAGE_EXT=""
fi

if [[ "${BETA}" == "yes" ]]; then
    BETA_EXT="beta-"
else
    BETA_EXT=""
fi

REL_NAME="couchbase-lite-${BETA_EXT}release${STAGE_EXT}-${VERSION}-${RELEASE}"

rm -rf deb/${REL_NAME}

sed -e "s/%DISTRO_CODENAMES%/${DISTRO_CODENAMES}/g" deb/debian_control_files/DEBIAN/postinst.in > deb/debian_control_files/DEBIAN/postinst
sed -e "s/%DISTRO_CODENAMES%/${DISTRO_CODENAMES}/g" deb/debian_control_files/DEBIAN/preinst.in > deb/debian_control_files/DEBIAN/preinst

sed -e "s/%STAGING%/${STAGE_EXT}/g" \
    -e "s/%BETA%/${BETA_EXT}/g" \
    -e "s/%VERSION%/${VERSION}/g" \
    -e "s/%RELEASE%/${RELEASE}/g" \
    deb/tmpl/control.in > deb/debian_control_files/DEBIAN/control

mkdir -p deb/debian_control_files/etc/apt/sources.list.d
sed -e "s/%STAGING%/${STAGE_EXT}/g" \
    -e "s/%BETA%/${BETA_EXT}/g" \ 
    deb/tmpl/couchbase-lite.list.in \
    > deb/debian_control_files/etc/apt/sources.list.d/couchbase-lite.list

chmod 755 deb/debian_control_files/DEBIAN/{pre,post}inst

cp -pr deb/debian_control_files deb/${REL_NAME}
mkdir -p deb/${REL_NAME}/etc/apt/trusted.gpg.d
cp -p GPG-KEY-COUCHBASE-1.0 \
    deb/${REL_NAME}/etc/apt/trusted.gpg.d/couchbase-gpg.asc
sudo chown -R root:root deb/${REL_NAME}
dpkg-deb --build deb/${REL_NAME}
sudo chown -R ${USER}:${USER} deb/${REL_NAME}

popd

cp ${this_dir}/deb/${REL_NAME}.deb ${REL_NAME}-noarch.deb
