# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Test VMs for the BPF programs, as in ebpfdivert. Build the test binary on the host, then run
# it in one VM at a time and destroy the VM when done:
#
#   cargo test -p avulse-ebpf --test kernel --no-run      # prints target/debug/deps/kernel-…
#   vagrant up default
#   vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/kernel-… --nocapture"
#   vagrant destroy -f default
#
# "default" is Ubuntu 24.04 (kernel 6.8); "legacy" is Ubuntu 22.04 (kernel 5.15, the oldest
# kernel the Linux backend supports, with the strictest verifier). The binaries need nothing
# installed in the VM.

Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  config.vm.define "default", primary: true do |m|
    m.vm.box = "bento/ubuntu-24.04"
    m.vm.hostname = "avulse"
  end

  config.vm.define "legacy", autostart: false do |m|
    m.vm.box = "bento/ubuntu-22.04"
    m.vm.hostname = "avulse-legacy"
  end
end
