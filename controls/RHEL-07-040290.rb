# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040290 - The operating system must enable an application firewall, if available.'
control 'RHEL-07-040290' do
  impact 0.5
  title 'The operating system must enable an application firewall, if available.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.  Satisfies: SRG-OS-000480-GPOS-00227, SRG-OS-000480-GPOS-00231, SRG-OS-000480-GPOS-00232'
  tag 'stig', 'RHEL-07-040290'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040290_chk'
  tag fixid: 'F-RHEL-07-040290_fix'
  tag version: 'RHEL-07-040290'
  tag ruleid: 'RHEL-07-040290_rule'
  tag fixtext: 'Ensure the operating system\'s application firewall is enabled.

Install the “firewalld” package if it is not on the system with the following command:

# yum install firewalld

Start the firewall via systemctl with the following command:

# systemctl start firewalld'
  tag checktext: 'Verify the operating system enabled an application firewall.

Check to see if "firewalld" is installed with the following command:

# yum list installed | grep firewalld
firewalld-0.3.9-11.el7.noarch.rpm

If the “firewalld” package is not installed, ask the system administrator if another firewall application (such as iptables) is installed. If an application firewall is not installed, this is a finding. 

Check to see if the firewall is loaded and active with the following command:

# systemctl status firewalld - must show that the firewall if loaded and active
firewalld.service - firewalld - dynamic firewall daemon

   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Tue 2014-06-17 11:14:49 CEST; 5 days ago

If “firewalld” does not show a status of “loaded and active”, this is a finding. 

Check the state of the firewall:

# firewall-cmd --state 
running

If “firewalld” does not show a state of “running”, this is a finding.'

# START_DESCRIBE RHEL-07-040290
  describe service('firewalld') do
    it { should be_running }
    it { should be_enabled }
  end

  describe command('firewall-cmd --state') do
    its('stdout') { should match /^running/ }
    its('exit_status') { should eq 0 }
  end
# STOP_DESCRIBE RHEL-07-040290

end

