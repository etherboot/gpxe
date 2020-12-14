# -*- mode: ruby -*-
# vi: set ft=ruby :
# See https://docs.vagrantup.com for syntax

Vagrant.configure("2") do |config|
  config.vm.box = "hashicorp/precise32"
  config.vm.box_check_update = false
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y gcc binutils perl syslinux mtools make genisoimage
  SHELL
end
