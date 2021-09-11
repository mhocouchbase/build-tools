#!/bin/bash -e

# This script takes a version and release as arguments, before generating
# and testing .deb and .rpm packages for the couchbase package manager repos.
# Trigger it with:
#   ./go.sh [version] [release]
# e.g: ./go.sh 1.0 7

# Note: apt/yum output is suppressed unless $verbose is non-empty. Run with
# e.g. `verbose=1 ./go.sh 1.0 999` to see unrestricted output

[ "$2" = "" ] && (echo "Usage: ./go.sh [version] [release]" ; exit 1)

if [[ -n $3 ]]; then
    STAGING="yes"
    STAGE_EXT="-staging"
else
    STAGING="no"
    STAGE_EXT=""
fi

if [[ -n $4 ]]; then
    BETA="yes"
    BETA_EXT="beta-"
else
    BETA="no"
    BETA_EXT=""
fi

heading() {
    local text=$@
    echo
    for ((i=0; i<${#text}+8; i++)) do echo -n "#"; done
    echo
    echo "#   $@   #"
    for ((i=0; i<${#text}+8; i++)) do echo -n "#"; done
    echo
    echo
}

heading "Discovering targets"

# Derive targeted platform versions from files in product-metadata/couchbase-lite-c/repo_upload
apt_json=$(curl -L --silent https://raw.githubusercontent.com/couchbase/product-metadata/master/couchbase-lite-c/repo_upload/apt.json)

apt_versions=$(jq -r '.os_versions[] .full' <<< $apt_json)

# debian based distribution names - this is used to replace template
# strings in deb/debian_control_files/DEBIAN/{postinst,preinst}
distro_codenames=$(echo $(jq -r '.os_versions | keys[]' <<< $apt_json) | sed "s/ /|/g")

get_versions() {
    for apt_version in $apt_versions
    do
        name=$(grep -Eo "[a-z]+" <<< $apt_version)
        release=$(grep -Eo "[0-9\.]+" <<< $apt_version)
        if [ "$name" = "$1" ]
        then
          echo "$release"
        fi
    done
}

ubuntu_versions=("$(get_versions ubuntu)")
debian_versions=("$(get_versions debian)")

echo "Codenames: "$distro_codenames
echo "   Debian: "$debian_versions
echo "   Ubuntu: "$ubuntu_versions
echo "  Staging: "${STAGING}
echo "  Beta: "${BETA}

version=$1
release=$2

run_test() {
    # Takes 3 arguments, OS name (centos, debian or ubuntu), release version
    # and a test string - release version should match docker image tag
    [ "$3" = "" ] && echo "Fatal: Not enough arguments passed to run_test()" && exit 1
    local os_name=$1
    local os_ver=$2
    local test_cmd=$3
    heading "Testing ${os_name} ${os_ver}"
    if ! docker run --rm -it -v $(pwd):/app -w /app ${os_name}:${os_ver} bash -c "${test_cmd}"
    then
        failures="${failures}    ${os_name} ${os_ver}\n"
    fi
}

# Tidy up the output of previous runs
for ext in deb ; do [ -f couchbase-lite-release*.${ext} ] && rm couchbase-lite-release*.${ext}; done
rm -rf deb/couchbase-lite-release*

# If verbose is unset, suppress all test output except the results of package searches
[ "$verbose" = "" ] &&
  redirect_all=" &>/dev/null" && \
  redirect_stderr="2>/dev/null" && \
  yum_quiet="-q" && \
  apt_quiet="-qq"

# Debian and Ubuntu use the same test string
debian_test="command -v apt &>/dev/null && apt_cmd=apt || apt_cmd=apt-get && \
\${apt_cmd} ${apt_quiet} update ${redirect_all} && \
(\${apt_cmd} ${apt_quiet} install -y gpg ${redirect_all} \
  || \${apt_cmd} ${apt_quiet} install -y gpgv ${redirect_all} \
  || \${apt_cmd} ${apt_quiet} install -y gpgv2 ${redirect_all} ) && \
\${apt_cmd} ${apt_quiet} install -y lsb-release ${redirect_all} && \
dpkg -i couchbase-lite-${BETA_EXT}release${STAGE_EXT}-${version}-${release}*.deb ${redirect_all} && \
if ! update=\$(\${apt_cmd} update 2>&1); then stderr=${update} ; fi ; \
\${apt_cmd} ${apt_quiet} list -a '*couchbase-lite*' ${redirect_stderr} && \
echo ${stderr}"

# Create Ubuntu build image
heading "Creating/Updating Ubuntu build container image"
docker build -t couchbase-lite-release-ubuntu -<<EOF
FROM ubuntu:20.04
RUN apt update && apt install -y gpgv2 lsb-release sudo
EOF

# Create .deb
heading "Creating .deb"
docker run --rm -it -v $(pwd):/app -w /app couchbase-lite-release-ubuntu bash -c \
  "VERSION=${version} RELEASE=${release} DISTRO_CODENAMES=\"${distro_codenames}\" ./build_deb.sh ${STAGING} ${BETA}"

if [ "$run_tests" = "no" ]; then exit 0; fi

# Run tests
for os in ${debian_versions[@]}; do run_test debian ${os} "${debian_test}"; done
for os in ${ubuntu_versions[@]}; do run_test ubuntu ${os} "${debian_test}"; done

# Show output
if [ "${warnings}" != "" ];
then
  heading "WARNINGS"
  printf "${warnings}"
fi

if [ "${failures}" != "" ];
then
  heading "FAILED"
  printf "Fatal: Investigate failures affecting:\n${failures}\n"
  exit 1
else
  heading "All OK"
fi
