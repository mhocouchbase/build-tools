#!/bin/bash -ex

pwd

# cleanup unwanted stuff
# doc directory leads to wrong components and cves
# also remove first-party code such as fleece.
find . -type d -name "doc" | xargs rm -rf
