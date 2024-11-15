packer {
  required_version = ">= 1.7.0"
  required_plugins {
    amazon = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-west-2"
}

source "amazon-ebs" "ubuntu" {
  ami_name                = "sbtc-signer-image-{{timestamp}}"
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
    volume_size           = 100
    volume_type           = "gp3"
    delete_on_termination = true
  }
}

build {
  sources = ["source.amazon-ebs.ubuntu"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y docker.io docker-compose git",
      "sudo usermod -aG docker ubuntu",
      "git clone https://github.com/stacks-network/sbtc.git",
      "cd sbtc",
      "",
      "curl -O https://archive.hiro.so/testnet/stacks-blockchain/testnet-stacks-blockchain-2.5.0.0.7-20240917.tar.gz",
      "sudo docker-compose -f docker/docker-compose.yml --profile sbtc-signer up",
    ]
  }
}
