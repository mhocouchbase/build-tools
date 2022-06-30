variable "product_name" {
  type = string
}

variable "product_version" {
  type = string
}

variable "product_bld_num" {
  type = string
}

variable "ami_name" {
  type = string
}

variable "region" {
  type = string
}

variable "dp_service" {
  type = string
}

variable "enableServerless" {
  type = string
}

locals {
  dp_backup_service = "dp-backup"
  setupDPBackupRsyslog = "sudo sh -c 'mv /tmp/dp-backup.conf /etc/rsyslog.d/dp-backup.conf && sudo systemctl restart rsyslog'"
  // only inject rsyslog conf for dp-backup
  useDPBackupConf = var.dp_service == local.dp_backup_service ? local.setupDPBackupRsyslog : ""

  setupServerless = "sudo mkdir -p /etc/couchbase.d && sudo bash -c 'echo serverless > /etc/couchbase.d/config_profile' && sudo chmod 755 /etc/couchbase.d/config_profile && sudo chown -R couchbase:couchbase /etc/couchbase.d"
  enableServerless = "true"
  serverlessConfig = var.enableServerless == local.enableServerless ? local.setupServerless : ""
}

source "amazon-ebs" "cc" {
  ami_name      = "${var.ami_name}"
  instance_type = "t2.micro"
  region        = "${var.region}"
  // No permission to create SG on stage, have to use an existing SG
  //security_group_id = "sg-082125705b63f8216"
  source_ami_filter {
    filters = {
      name                = "amzn2-ami-hvm-2.0.*-x86_64-gp2"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["amazon"]
  }
  tags = {
    service     = "${var.product_name}"
  }
  snapshot_tags = {
    service     = "${var.product_name}"
  }
  ssh_username = "ec2-user"
}

# a build block invokes sources and runs provisioning steps on them.
build {
  sources = ["source.amazon-ebs.cc"]

  provisioner "file" {
    destination = "/tmp/"
    source      = "couchbase-server-enterprise-${var.product_version}-${var.product_bld_num}-amzn2.x86_64.rpm"
  }

  provisioner "file" {
    destination = "/tmp/"
    source      = "${var.dp_service}.gz"
  }

  provisioner "file" {
    destination = "/tmp/"
    source      = "${var.dp_service}.service"
  }

  provisioner "file" {
    destination = "/tmp/"
    source      = "node-exporter.service"
  }

  provisioner "file" {
    destination = "/tmp/"
    source      = "process-exporter.service"
  }


  provisioner "file" {
    destination = "/tmp/disable-thp"
    source      = "disable-thp"
  }

  provisioner "file" {
    destination = "/tmp/dp-backup.conf"
    source = "dp-backup.conf"
  }

  provisioner "file" {
    destination = "/tmp/journald.conf"
    source = "journald.conf"
  }

  provisioner "file" {
   destination = "/tmp/iptables-firewall.sh"
   source = "iptables-firewall.sh"
  }

  provisioner "file" {
   destination = "/tmp/dp-firewall.service"
   source = "dp-firewall.service"
  }

  provisioner "shell" {
    inline = [
      "sleep 10",
      "sudo mv /tmp/disable-thp /etc/init.d/disable-thp",
      "sudo chmod 755 /etc/init.d/disable-thp",
      "sudo chkconfig --add disable-thp",
      "sudo mv /tmp/journald.conf /etc/systemd/journald.conf",
      "sudo chown root:root /etc/systemd/journald.conf",
      "sudo chmod 755 /etc/systemd/journald.conf",
      // Set swappiness to 1 to avoid swapping excessively
      "sudo sh -c 'echo \"vm.swappiness = 1\" >> /etc/sysctl.conf'",
      "sudo yum install -y /tmp/couchbase-server-enterprise-${var.product_version}-${var.product_bld_num}-amzn2.x86_64.rpm",
      "rm /tmp/couchbase-server-enterprise-${var.product_version}-${var.product_bld_num}-amzn2.x86_64.rpm",
      // Setup the directory for the TLS certificate and key
      "sudo usermod -a -G couchbase ec2-user",
      "sudo mkdir /opt/couchbase/var/lib/couchbase/inbox/",
      "sudo touch /opt/couchbase/var/lib/couchbase/inbox/chain.pem",
      "sudo touch /opt/couchbase/var/lib/couchbase/inbox/pkey.key",
      "sudo chown -R ec2-user:couchbase /opt/couchbase/var/lib/couchbase/inbox/",
      "sudo chmod 0640 /opt/couchbase/var/lib/couchbase/inbox/chain.pem",
      "sudo chmod 0640 /opt/couchbase/var/lib/couchbase/inbox/pkey.key",
      "sudo systemctl disable couchbase-server",
      // Install and start node exporter
      "sudo wget https://github.com/prometheus/node_exporter/releases/download/v1.1.2/node_exporter-1.1.2.linux-amd64.tar.gz -P /tmp/",
      "sudo tar xvfz /tmp/node_exporter-1.1.2.linux-amd64.tar.gz -C /tmp",
      "sudo rm /tmp/node_exporter-1.1.2.linux-amd64.tar.gz",
      "sudo mv /tmp/node_exporter-1.1.2.linux-amd64/node_exporter /home/ec2-user/node_exporter",
      "sudo chown ec2-user:ec2-user /home/ec2-user/node_exporter",
      "sudo mv /tmp/node-exporter.service /lib/systemd/system/node-exporter.service",
      "sudo systemctl enable node-exporter.service",
      // Install and enable process exporter
      "sudo wget https://github.com/ncabatoff/process-exporter/releases/download/v0.7.5/process-exporter_0.7.5_linux_amd64.rpm -P /tmp/",
      "sudo rpm --install /tmp/process-exporter_0.7.5_linux_amd64.rpm",
      "sudo rm /tmp/process-exporter_0.7.5_linux_amd64.rpm",
      "sudo mv /tmp/process-exporter.service /lib/systemd/system/process-exporter.service",
      "sudo systemctl enable process-exporter.service",
      // Install and enable dp-agent
      "sudo mv /tmp/${var.dp_service}.service /lib/systemd/system/${var.dp_service}.service",
      "sudo mv /tmp/${var.dp_service}.gz /home/ec2-user",
      "sudo gunzip /home/ec2-user/${var.dp_service}.gz",
      "sudo chmod +x /home/ec2-user/${var.dp_service}",
      "sudo systemctl enable ${var.dp_service}.service",
      // Install firewall service
      "sudo mv /tmp/dp-firewall.service /lib/systemd/system/dp-firewall.service",
      "sudo mv /tmp/iptables-firewall.sh /home/ec2-user",
      "sudo chmod +x /home/ec2-user/iptables-firewall.sh",
      "sudo chown root:root /home/ec2-user/iptables-firewall.sh",
      "sudo systemctl start dp-firewall.service",
      "sudo systemctl enable dp-firewall.service",
      // Add imports directory
      "sudo mkdir -p /home/ec2-user/imports",
      "sudo chown ec2-user:ec2-user /home/ec2-user/imports",
      # Setup Rsyslog conf for dp-backup
      "${local.useDPBackupConf}",
      # Custom packages for perf
      "sudo amazon-linux-extras install epel",
      "sudo yum -y install sysstat atop --enablerepo=epel",
      "sudo sed -i 's/^LOGINTERVAL=600.*/LOGINTERVAL=60/' /etc/sysconfig/atop",
      "sudo sed -i -e 's|*/10|*/1|' -e 's|every 10 minutes|every 1 minute|' /etc/cron.d/sysstat",
      "sudo systemctl enable atop.service crond.service sysstat.service",
      "sudo yum -y install fio gdb hdparm htop iotop iperf kernel-devel kernel-headers java-1.8.0-openjdk lsof moreutils net-tools numactl psmisc rsync sysstat tree vim wget perf zip",
      # Enable serverless
      "${local.serverlessConfig}"
    ]
  }
}


