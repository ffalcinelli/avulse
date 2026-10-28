# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Test VMs for the BPF programs, as in ebpfdivert. Build the test binary on the host, then run
# it in one VM at a time and destroy the VM when done:
#
#   cargo test -p avulse-ebpf --test kernel --no-run      # prints target/debug/deps/kernel-…
#   cargo test -p avulse --test capture --no-run          # prints target/debug/deps/capture-…
#   vagrant up default
#   vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/kernel-… --nocapture"
#   vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/capture-… --test-threads=1"
#   vagrant destroy -f default
#
# "default" is Ubuntu 24.04 (kernel 6.8); "legacy" is Ubuntu 22.04 (kernel 5.15, the oldest
# kernel the Linux backend supports, with the strictest verifier). The binaries need nothing
# installed in the VM.
#
# "windows" (Windows 11 24H2) builds and loads the Windows driver (drivers/windows, and the
# spike in spikes/windows-driver). Its provisioning installs the driver toolchain and turns on
# test signing and Driver Verifier, which take effect after a reboot:
#
#   vagrant up windows && vagrant reload windows
#   vagrant winrm windows -e -c "C:\avulse\drivers\windows\scripts\build.ps1"
#   vagrant winrm windows -e -c "C:\avulse\drivers\windows\scripts\test.ps1"
#   vagrant destroy -f windows

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

  config.vm.define "windows", autostart: false do |m|
    m.vm.box = "gusztavvargadr/windows-11-24h2-enterprise"
    m.vm.communicator = "winrm"
    m.vm.boot_timeout = 900
    m.winrm.timeout = 3600
    m.vm.synced_folder ".", "/vagrant", disabled: true
    m.vm.synced_folder ".", "C:/avulse"
    m.vm.provider "virtualbox" do |vb|
      vb.memory = "6144"
      vb.cpus = 4
      vb.customize ["modifyvm", :id, "--vram", "128"]
    end
    m.vm.provision "toolchain", type: "shell", path: "spikes/windows-driver/scripts/toolchain.ps1"
  end
end
