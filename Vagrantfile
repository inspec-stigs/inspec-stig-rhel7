# -*- mode: ruby -*-
# vi: set ft=ruby :

$inspec_url = 'https://packages.chef.io/stable/el/7/inspec-1.6.0-1.el7.x86_64.rpm'

Vagrant.configure(2) do |config|
  config.vm.box = "centos/7"
  config.vm.synced_folder ".", "/vagrant", type: "nfs"
  config.vm.network :private_network, ip: "172.16.0.100"
  config.vm.provision "shell", inline: <<-SHELL
     rpm -qa | grep inspec || sudo yum install -y $inspec_url
  SHELL
end
