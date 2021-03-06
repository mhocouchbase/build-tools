#!/bin/sh -e

PRODUCT=${1}
RELEASE=${2}

[ -z ${GID} ] && GID=1000
[ -z ${PID} ] && PID=1000

group=$(cat /etc/group | grep "\:${GID}\:" | awk -F: '{print $1}')

if [ -z "$group" ]
then
  group=couchbase
  addgroup -g ${GID} ${group}
fi

adduser -D -G ${group} -u ${PID} couchbase

mkdir -p /home/couchbase/.ssh
chown -R couchbase:${group} . /home/couchbase

su-exec couchbase sh -c "ssh-keyscan github.com >> ~/.ssh/known_hosts && \
                         git config --global user.name \"${git_user_name}\" && \
                         git config --global user.email \"${git_user_email}\" && \
                         git config --global color.ui auto && \
                         /app/jenkins/run_missing_commit_check.sh ${PRODUCT} ${RELEASE}"
