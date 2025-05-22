#!/bin/bash -ex

RELEASE=$1
VERSION=$2
BLD_NUM=$3
TOOLS_DIR=$4

shopt -s extglob

# NPM-related stuff - see CBD-3365

# Most of this stuff is npm-generated "compiled" code; we ONLY want
# to scan the npm package.json/package-lock.json files
mv ns_server/priv/public/ui/package*.json ns_server/priv
rm -rf ns_server/priv/public

for pkg in angular-bootstrap angular-route angular; do
  rm -rf cbgt/rest/static/lib/${pkg}/!(package*.json)
done

# Server doesn't use asterix's dashboard, so prune that
rm analytics/asterixdb/asterixdb/asterix-dashboard/src/node/package.json

# This is build-time only, not shipped. (The directory name has changed over
# time.)
rm -f query-ui/query-ui/n1ql_parser/package.json
rm -f query-ui/query-ui/parser/antlr_runtime/package.json

# Server doesn't use any of bleve-mapping-ui's NPM components, so eliminate them
rm -rf godeps/src/github.com/blevesearch/bleve-mapping-ui/bower_components

# END NPM-related stuff

# Need to save any of these before deleting the rest of cbbuild
find cbbuild -name couchbase-server-black-duck-manifest.yaml -print0 | xargs -0 -I FILENAME cp FILENAME .

# cleanup unwanted stuff - test files, build scripts, etc.
rm -rf testrunner
rm -rf cbbuild
rm -rf goproj/src/github.com/couchbase/query/data/sampledb
rm -rf goproj/src/github.com/couchbase/docloader/examples
rm -rf goproj/src/github.com/couchbase/indexing/secondary/docs
find . -name rebar -print0 | xargs -0 rm -rf

# General-purpose removal of test data, examples, docs, etc.
find . -name analytics -prune -o -name regulator -prune -o -type d -name test\* -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name testdata -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name gtest -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name testing -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name \*tests -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -name backup -prune -o -name indexing -prune -o -type d -name data -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name docs -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name example -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name examples -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name samples -print0 | xargs -0 rm -rf
find . -name analytics -prune -o -type d -name benchmarks -print0 | xargs -0 rm -rf

# godeps-specific pruning (hopefully eliminated after switching entirely to Go modules)
rm -rf godeps/src/golang.org/x/tools/cmd/heapview/client

# We don't need to pull in all transitive dependencies of godeps (if they're under
# godeps, by definition we're building them using GOPATH rather than Go modules, so
# only stuff that's actually here will be compiled). However, things from couchbase
# or couchbaselabs under godeps (in particular gocb) might be referenced by other
# projects' go.mod via replace directives, so we need to leave those there.
find godeps -name 'couchbase*' -prune -o -name go.mod -print0 | xargs -0 rm -f

# Remove all msvc, vcs* window projects
WIN='example *msvc* *vcproj* *vcxproj* visual vstudio dot_net_example example csharp vc7ide'
for windir in ${WIN}; do
    find . -name analytics -prune -o -type d -name "$windir" -print0 | xargs -0 rm -rf
done
