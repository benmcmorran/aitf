# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty32"

  config.vm.define "host1" do |config|
    config.vm.network "private_network", ip: "192.168.10.10", virtualbox__intnet: "net1"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route del default
      sudo ip route add default via 192.168.10.11
    SHELL
  end

  config.vm.define "node1" do |config|
    config.vm.network "private_network", ip: "192.168.10.11", virtualbox__intnet: "net1"
    config.vm.network "private_network", ip: "192.168.100.10", virtualbox__intnet: "net2"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route add 192.168.20.0/24 via 192.168.100.11
      sudo sysctl net.ipv4.ip_forward=1
    SHELL
  end

  config.vm.define "node2" do |config|
    config.vm.network "private_network", ip: "192.168.100.11", virtualbox__intnet: "net2"
    config.vm.network "private_network", ip: "192.168.20.11", virtualbox__intnet: "net3"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route add 192.168.10.0/24 via 192.168.100.10
      sudo sysctl net.ipv4.ip_forward=1
    SHELL
  end

  config.vm.define "host2" do |config|
    config.vm.network "private_network", ip: "192.168.20.10", virtualbox__intnet: "net3"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route del default
      sudo ip route add default via 192.168.20.11
    SHELL
  end
end
