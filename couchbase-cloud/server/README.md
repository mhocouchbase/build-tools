#### Overview
The image building process starts with building an image using packer. This requires an HCL file in the form $name.pkr.hcl. The example provided will allow for the building of an image in a single region. This is useful for testing but not the manner in which image distribution will occur. Once successfully built and the image is "available" you can provision new clusters using it. To do so change the image / release in `internal/clusters/versions`. The resulting images do cost money. Please be cognizant of this and clean up after yourself when testing a new image(s). 

Example of process for building image for Couchbase Server nodes:
```
cd cmd/dp-agent-v2
GOOS=linux GOARCH=amd64 go build -o dp-agent -ldflags="-X 'main.Provider=aws'"
mv dp-agent ../../internal/clusters/images/aws
cd ../../internal/clusters/images/aws
gzip dp-agent
vim .env to modify environment
source .env
packer validate couchbase-cloud.pkr.hcl 
AWS_PROFILE=dbaas-test-0005-temp packer build couchbase-cloud.pkr.hcl
```

Expected output from run:
```
amazon-ebs.cc: output will be in this color.

==> amazon-ebs.cc: Prevalidating any provided VPC information
==> amazon-ebs.cc: Prevalidating AMI Name: couchbase-cloud-server-v0.1.17
    amazon-ebs.cc: Found Image ID: ami-0dd273d94ed0540c0
==> amazon-ebs.cc: Creating temporary keypair: packer_608ec532-e061-dae9-791f-eed0081ef10a
==> amazon-ebs.cc: Creating temporary security group for this instance: packer_608ec535-145e-956c-fc73-102e61f6cdcc
==> amazon-ebs.cc: Authorizing access to port 22 from [0.0.0.0/0] in the temporary security groups...
==> amazon-ebs.cc: Launching a source AWS instance...
==> amazon-ebs.cc: Adding tags to source instance
    amazon-ebs.cc: Adding tag: "Name": "Packer Builder"
    amazon-ebs.cc: Instance ID: i-02dd58cfe322aa984
==> amazon-ebs.cc: Waiting for instance (i-02dd58cfe322aa984) to become ready...
==> amazon-ebs.cc: Using ssh communicator to connect: 54.212.154.128
==> amazon-ebs.cc: Waiting for SSH to become available...
==> amazon-ebs.cc: Connected to SSH!
==> amazon-ebs.cc: Uploading dp-agent.gz => /tmp/
    amazon-ebs.cc: dp-agent.gz 4.90 MiB / 4.90 MiB [=========================================================================================================================================================] 100.00% 1s
==> amazon-ebs.cc: Uploading dp-agent.service => /tmp/
    amazon-ebs.cc: dp-agent.service 602 B / 602 B [==========================================================================================================================================================] 100.00% 0s
==> amazon-ebs.cc: Provisioning with shell script: /var/folders/m2/f8y17_nd7xvg63m8b964ff8w0000gp/T/packer-shell311288425
==> amazon-ebs.cc:   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
==> amazon-ebs.cc:                                  Dload  Upload   Total   Spent    Left  Speed
==> amazon-ebs.cc: 100  5184  100  5184    0     0   7404      0 --:--:-- --:--:-- --:--:--  7395
    amazon-ebs.cc: Selecting previously unselected package couchbase-release.
    amazon-ebs.cc: (Reading database ... 51474 files and directories currently installed.)
    amazon-ebs.cc: Preparing to unpack .../couchbase-release-1.0-amd64.deb ...
    amazon-ebs.cc: Unpacking couchbase-release (1.0-9) ...
    amazon-ebs.cc: Setting up couchbase-release (1.0-9) ...
==> amazon-ebs.cc: gpg: directory `/home/ubuntu/.gnupg' created
==> amazon-ebs.cc: gpg: new configuration file `/home/ubuntu/.gnupg/gpg.conf' created
==> amazon-ebs.cc: gpg: WARNING: options in `/home/ubuntu/.gnupg/gpg.conf' are not yet active during this run
==> amazon-ebs.cc: gpg: keyring `/home/ubuntu/.gnupg/secring.gpg' created
==> amazon-ebs.cc: gpg: keyring `/home/ubuntu/.gnupg/pubring.gpg' created
==> amazon-ebs.cc: gpg: /home/ubuntu/.gnupg/trustdb.gpg: trustdb created
==> amazon-ebs.cc: gpg: key CD406E62: public key "Couchbase Release Key (RPM) <support@couchbase.com>" imported
==> amazon-ebs.cc: gpg: key D9223EDA: public key "Couchbase Release Key <support@couchbase.com>" imported
==> amazon-ebs.cc: gpg: key 79CF7903: public key "Couchbase Builder Key <support@couchbase.com>" imported
==> amazon-ebs.cc: gpg: Total number processed: 3
==> amazon-ebs.cc: gpg:               imported: 3  (RSA: 2)
    amazon-ebs.cc: OK
    amazon-ebs.cc: Hit:1 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial InRelease
    amazon-ebs.cc: Get:2 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-updates InRelease [109 kB]
    amazon-ebs.cc: Get:3 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-backports InRelease [107 kB]
    amazon-ebs.cc: Get:4 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial/universe amd64 Packages [7,532 kB]
    amazon-ebs.cc: Get:5 http://security.ubuntu.com/ubuntu xenial-security InRelease [109 kB]
    amazon-ebs.cc: Get:6 http://packages.couchbase.com/releases/couchbase-server/enterprise/deb xenial InRelease [4,121 B]
    amazon-ebs.cc: Get:7 http://packages.couchbase.com/releases/couchbase-server/community/deb xenial InRelease [4,121 B]
    amazon-ebs.cc: Get:8 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial/universe Translation-en [4,354 kB]
    amazon-ebs.cc: Get:9 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial/multiverse amd64 Packages [144 kB]
    amazon-ebs.cc: Get:10 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial/multiverse Translation-en [106 kB]
    amazon-ebs.cc: Get:11 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages [2,048 kB]
    amazon-ebs.cc: Get:12 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-updates/main Translation-en [482 kB]
    amazon-ebs.cc: Get:13 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-updates/universe amd64 Packages [1,220 kB]
    amazon-ebs.cc: Get:14 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-updates/universe Translation-en [358 kB]
    amazon-ebs.cc: Get:15 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-updates/multiverse amd64 Packages [22.6 kB]
    amazon-ebs.cc: Get:16 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-updates/multiverse Translation-en [8,476 B]
    amazon-ebs.cc: Get:17 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-backports/main amd64 Packages [9,812 B]
    amazon-ebs.cc: Get:18 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-backports/main Translation-en [4,456 B]
    amazon-ebs.cc: Get:19 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-backports/universe amd64 Packages [11.3 kB]
    amazon-ebs.cc: Get:20 http://us-west-2.ec2.archive.ubuntu.com/ubuntu xenial-backports/universe Translation-en [4,476 B]
    amazon-ebs.cc: Get:21 http://packages.couchbase.com/releases/couchbase-server/enterprise/deb xenial/xenial/main amd64 Packages [5,516 B]
    amazon-ebs.cc: Get:22 http://packages.couchbase.com/releases/couchbase-server/community/deb xenial/xenial/main amd64 Packages [2,322 B]
    amazon-ebs.cc: Get:23 http://security.ubuntu.com/ubuntu xenial-security/main amd64 Packages [1,646 kB]
    amazon-ebs.cc: Get:24 http://security.ubuntu.com/ubuntu xenial-security/universe amd64 Packages [786 kB]
    amazon-ebs.cc: Get:25 http://security.ubuntu.com/ubuntu xenial-security/universe Translation-en [226 kB]
    amazon-ebs.cc: Get:26 http://security.ubuntu.com/ubuntu xenial-security/multiverse amd64 Packages [7,864 B]
    amazon-ebs.cc: Get:27 http://security.ubuntu.com/ubuntu xenial-security/multiverse Translation-en [2,672 B]
    amazon-ebs.cc: Fetched 19.3 MB in 3s (5,076 kB/s)
    amazon-ebs.cc: Reading package lists...
    amazon-ebs.cc: Reading package lists...
    amazon-ebs.cc: Building dependency tree...
    amazon-ebs.cc: Reading state information...
    amazon-ebs.cc: The following NEW packages will be installed:
    amazon-ebs.cc:   couchbase-server
    amazon-ebs.cc: 0 upgraded, 1 newly installed, 0 to remove and 18 not upgraded.
    amazon-ebs.cc: Need to get 354 MB of archives.
    amazon-ebs.cc: After this operation, 896 MB of additional disk space will be used.
    amazon-ebs.cc: Get:1 http://packages.couchbase.com/releases/couchbase-server/enterprise/deb xenial/xenial/main amd64 couchbase-server amd64 6.6.2-9588-1 [354 MB]
==> amazon-ebs.cc: debconf: unable to initialize frontend: Dialog
==> amazon-ebs.cc: debconf: (Dialog frontend will not work on a dumb terminal, an emacs shell buffer, or without a controlling terminal.)
==> amazon-ebs.cc: debconf: falling back to frontend: Readline
==> amazon-ebs.cc: debconf: unable to initialize frontend: Readline
==> amazon-ebs.cc: debconf: (This frontend requires a controlling tty.)
==> amazon-ebs.cc: debconf: falling back to frontend: Teletype
==> amazon-ebs.cc: dpkg-preconfigure: unable to re-open stdin:
    amazon-ebs.cc: Fetched 354 MB in 12s (27.7 MB/s)
    amazon-ebs.cc: Selecting previously unselected package couchbase-server.
    amazon-ebs.cc: (Reading database ... 51476 files and directories currently installed.)
    amazon-ebs.cc: Preparing to unpack .../couchbase-server_6.6.2-9588-1_amd64.deb ...
    amazon-ebs.cc: Warning: Transparent hugepages looks to be active and should not be.
    amazon-ebs.cc: Please look at https://docs.couchbase.com/server/6.6/install/thp-disable.html as for how to PERMANENTLY alter this setting.
    amazon-ebs.cc: Warning: Swappiness is not set to 0.
    amazon-ebs.cc: Please look at https://docs.couchbase.com/server/6.6/install/install-swap-space.html as for how to PERMANENTLY alter this setting.
    amazon-ebs.cc: Minimum RAM required  : 4 GB
    amazon-ebs.cc: System RAM configured : 0.97 GB
    amazon-ebs.cc:
    amazon-ebs.cc: Minimum number of processors required : 4 cores
    amazon-ebs.cc: Number of processors on the system    : 1 cores
    amazon-ebs.cc: Unpacking couchbase-server (6.6.2-9588-1) ...
    amazon-ebs.cc: Setting up couchbase-server (6.6.2-9588-1) ...
    amazon-ebs.cc:
    amazon-ebs.cc: You have successfully installed Couchbase Server.
    amazon-ebs.cc: Please browse to http://ip-172-31-2-76:8091/ to configure your server.
    amazon-ebs.cc: Refer to https://docs.couchbase.com for additional resources.
    amazon-ebs.cc:
    amazon-ebs.cc: Please note that you have to update your firewall configuration to
    amazon-ebs.cc: allow external connections to a number of network ports for full
    amazon-ebs.cc: operation. Refer to the documentation for the current list:
    amazon-ebs.cc: https://docs.couchbase.com/server/6.6/install/install-ports.html
    amazon-ebs.cc:
    amazon-ebs.cc: By using this software you agree to the End User License Agreement.
    amazon-ebs.cc: See /opt/couchbase/LICENSE.txt.
    amazon-ebs.cc:
==> amazon-ebs.cc: Created symlink from /etc/systemd/system/multi-user.target.wants/dp-agent.service to /lib/systemd/system/dp-agent.service.
==> amazon-ebs.cc: Stopping the source instance...
    amazon-ebs.cc: Stopping instance
==> amazon-ebs.cc: Waiting for the instance to stop...
==> amazon-ebs.cc: Creating AMI couchbase-cloud-server-v0.1.17 from instance i-02dd58cfe322aa984
    amazon-ebs.cc: AMI: ami-01aceae739bc0e86d
==> amazon-ebs.cc: Waiting for AMI to become ready...
==> amazon-ebs.cc: Terminating the source AWS instance...
==> amazon-ebs.cc: Cleaning up any extra volumes...
==> amazon-ebs.cc: No volumes to clean up, skipping
==> amazon-ebs.cc: Deleting temporary security group...
==> amazon-ebs.cc: Deleting temporary keypair...
Build 'amazon-ebs.cc' finished after 6 minutes 51 seconds.

==> Wait completed after 6 minutes 51 seconds

==> Builds finished. The artifacts of successful builds are:
--> amazon-ebs.cc: AMIs were created:
us-west-2: ami-01aceae739bc0e86d
```
