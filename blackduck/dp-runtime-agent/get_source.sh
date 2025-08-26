#!/bin/bash -ex

# example usage
# get_source.sh vulcan 1.0.0 1.0.0 9999

# Set to "vulcan", ignored in this script.
PRODUCT=$1
# By default this will be the same as VERSION; however, if your
# scan-config.json specified a release key for this version, that value
# will be passed here
RELEASE=$2
# One of the version keys from scan-config.json.
VERSION=$3
# Set to 9999, ignored in this script as it is not useful for SDK scans.
BLD_NUM=$4

git clone ssh://git@github.com/couchbasecloud/couchbase-cloud.git
pushd couchbase-cloud
git checkout $RELEASE
# Use the same go version used on self hosted runners
GO_VER=$(yq '.inputs.go-version.default' .github/actions/setup-go/action.yml)
cbdep install -d "${WORKSPACE}/extra" golang ${GO_VER}
export PATH="${WORKSPACE}/extra/go${GO_VER}/bin:$PATH"
rm -rf vendor/
export GOMODCACHE=$(mktemp -d)
cd cmd/dp-runtime-agent
go mod init couchbase-cloud/cmd/dp-runtime-agent
cat ${PROD_DIR}/go.mod.replace >> go.mod
go mod tidy
# Go through each module and determine if it's unused
echo "Analyzing unused modules..."
unused_modules=$(go mod why -m all 2>/dev/null | \
  awk -F '[() ]+' '/main module does not need module / {print $(NF-1)}' \
  | grep -v 'k8s.io/controller-manager' | sort | uniq)

if [[ -z "$unused_modules" ]]; then
  echo "No unused modules found."
fi
echo "Unused modules:"
echo "$unused_modules"
echo

# Remove unused modules from go.mod
for mod in $unused_modules; do
  echo "Removing $mod from go.mod..."
  # Drop replace directives (if any)
  go mod edit -dropreplace=$mod 2>/dev/null || true
  # Try to remove the module
  # go get $mod@none 2>/dev/null || true
done

# Clean up go.mod and go.sum
echo "Running go mod tidy..."
rm -rf vendor/
export GOMODCACHE=$(mktemp -d)
go mod tidy

echo "Cleanup complete."
