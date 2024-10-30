#!/bin/bash -ex
rm -rf build manifest.xml
rm -rf vulcan-core/test*
pushd vulcan-core/libs/vulcan/extractor
pip install -r requirements.txt
popd
