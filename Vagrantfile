# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "netsec"

  config.vm.define "host1" do |config|
    config.vm.network "private_network", ip: "192.168.10.10", virtualbox__intnet: "net10"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route del default
      sudo ip route add default via 192.168.10.100
    SHELL
  end

  config.vm.define "host2" do |config|
    config.vm.network "private_network", ip: "192.168.20.10", virtualbox__intnet: "net20"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route del default
      sudo ip route add default via 192.168.20.100
    SHELL
  end

  config.vm.define "host3" do |config|
    config.vm.network "private_network", ip: "192.168.30.10", virtualbox__intnet: "net30"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route del default
      sudo ip route add default via 192.168.30.100
    SHELL
  end

  config.vm.define "host4" do |config|
    config.vm.network "private_network", ip: "192.168.30.20", virtualbox__intnet: "net30"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route del default
      sudo ip route add default via 192.168.30.100
    SHELL
  end

  config.vm.define "node1" do |config|
    config.vm.network "private_network", ip: "192.168.10.100", virtualbox__intnet: "net10"
    config.vm.network "private_network", ip: "192.168.100.10", virtualbox__intnet: "net100"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route add 192.168.20.0/24 via 192.168.100.20
      sudo ip route add 192.168.30.0/24 via 192.168.100.20
      sudo ip route add 192.168.200.0/24 via 192.168.100.20
      sudo sysctl net.ipv4.ip_forward=1
    SHELL
  end

  config.vm.define "node2" do |config|
    config.vm.network "private_network", ip: "192.168.100.20", virtualbox__intnet: "net100"
    config.vm.network "private_network", ip: "192.168.20.100", virtualbox__intnet: "net20"
    config.vm.network "private_network", ip: "192.168.200.10", virtualbox__intnet: "net200"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route add 192.168.10.0/24 via 192.168.100.10
      sudo ip route add 192.168.30.0/24 via 192.168.200.20
      sudo sysctl net.ipv4.ip_forward=1
    SHELL
  end

  config.vm.define "node3" do |config|
    config.vm.network "private_network", ip: "192.168.200.20", virtualbox__intnet: "net200"
    config.vm.network "private_network", ip: "192.168.30.100", virtualbox__intnet: "net30"
    config.vm.provision "shell", inline: <<-SHELL
      sudo ip route add 192.168.10.0/24 via 192.168.200.10
      sudo ip route add 192.168.20.0/24 via 192.168.200.10
      sudo ip route add 192.168.100.0/24 via 192.168.200.10
      sudo sysctl net.ipv4.ip_forward=1
    SHELL
  end
end
