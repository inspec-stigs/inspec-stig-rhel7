# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040820 - The system\'s access control program must be configured to grant or deny system access to specific hosts and services.'
control 'RHEL-07-040820' do
  impact 0.5
  title 'The system\'s access control program must be configured to grant or deny system access to specific hosts and services.'
  desc 'If the systems access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts.'
  tag 'stig', 'RHEL-07-040820'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040820_chk'
  tag fixid: 'F-RHEL-07-040820_fix'
  tag version: 'RHEL-07-040820'
  tag ruleid: 'RHEL-07-040820_rule'
  tag fixtext: 'If “firewalld” is installed and active on the system, configure rules for allowing specific services and hosts.

If “tcpwrappers” is installed. configure the “/etc/hosts.allow” and “/etc/hosts.deny” to allow or deny access to specific hosts.'
  tag checktext: 'If the “firewalld” package is not installed, ask the System Administrator if another firewall application (such as iptables) is installed. If an application firewall is not installed, this is a finding.

Verify the system\'s access control program is configured to grant or deny system access to specific hosts.

Check to see if “firewalld” is active with the following command:

# systemctl status firewalld
firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago

If “firewalld” is active, check to see if it is configured to grant or deny access to specific hosts or services with the following commands:

# firewall-cmd --get-default-zone
public

# firewall-cmd --list-all --zone=public
public (default, active)
  interfaces: eth0
  sources:
  services: mdns ssh
  ports:
  masquerade: no
  forward-ports:
  icmp-blocks:
  rich rules:
 rule family="ipv4" source address="92.188.21.1/24" accept
 rule family="ipv4" source address="211.17.142.46/32" accept

If “firewalld” is not active, determine whether “tcpwrappers” is being used by checking whether the “hosts.allow” and “hosts.deny” files are empty with the following commands:

# ls -al /etc/hosts.allow
rw-r----- 1 root root 9 Aug  2 23:13 /etc/hosts.allow

# ls -al /etc/hosts.deny
-rw-r----- 1 root root  9 Apr  9  2007 /etc/hosts.deny

If “firewalld” and “tcpwrappers” are not installed, configured, and active, ask the System Administrator (SA) if another access control program (such as iptables) is installed and active. Ask the SA to show that the running configuration grants or denies access to specific hosts or services.

If “firewalld” is active and is not configured to grant access to specific hosts and “tcpwrappers” is not configured to grant or deny access to specific hosts, this is a finding.'

# START_DESCRIBE RHEL-07-040820
  describe package('firewalld') do
    it { should be_installed }
  end

  describe service('firewalld') do
    it { should be_running }
    it { should be_enabled }
  end

  describe package('tcp_wrappers') do
    it { should be_installed }
  end

  describe package('tcp_wrappers-libs') do
    it { should be_installed }
  end

  describe.one do
    describe command('firewall-cmd --list-all') do
      its('stdout') { should match /source\s+address=".+"/ }
    end

    describe file('/etc/hosts.allow') do
      its('content') { should match /^(?!#).+$/ }
    end

    describe file('/etc/hosts.deny') do
      its('content') { should match /^(?!#).+$/ }
    end
  end
# STOP_DESCRIBE RHEL-07-040820

end

