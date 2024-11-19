packer {
  required_version = ">= 1.7.0"
  required_plugins {
    amazon = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_access_key" {
  type    = string
  default = ""
}

variable "aws_secret_key" {
  type    = string
  default = ""
}

variable "aws_region" {
  type    = string
  default = "us-west-2"
}

source "amazon-ebs" "ubuntu" {
  ami_name                = "sbtc-signer-image-{{timestamp}}"
  access_key    = var.aws_access_key
  secret_key    = var.aws_secret_key
  instance_type           = "c6i.xlarge"
  region                  = var.aws_region
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"] # Canonical
    most_recent = true
  }
  ssh_username            = "ubuntu"
  ami_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 200
    volume_type           = "gp3"
    delete_on_termination = true
  }
}

build {
  sources = ["source.amazon-ebs.ubuntu"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y docker.io",
      "sudo curl -L \"https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose",
      "sudo chmod +x /usr/local/bin/docker-compose",
      "sudo usermod -aG docker ubuntu",
      "git clone https://github.com/stacks-network/sbtc.git",
      "cd sbtc",
      "sudo docker-compose -f docker/prodlike/docker-compose.testnet.yml pull",
      "sudo docker-compose -f docker/prodlike/docker-compose.testnet.yml up -d",
    ]
  }
}
