# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040830 - The system must not have unauthorized IP tunnels configured.'
control 'RHEL-07-040830' do
  impact 0.5
  title 'The system must not have unauthorized IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the Information System Security Officer (ISSO).'
  tag 'stig', 'RHEL-07-040830'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040830_chk'
  tag fixid: 'F-RHEL-07-040830_fix'
  tag version: 'RHEL-07-040830'
  tag ruleid: 'RHEL-07-040830_rule'
  tag fixtext: 'Remove all unapproved tunnels from the system, or document them with the ISSO.'
  tag checktext: 'Verify the system does not have unauthorized IP tunnels configured.

Check to see if “libreswan” is installed with the following command:

# yum list installed libreswan
openswan-2.6.32-27.el6.x86_64

If “libreswan” is installed, check to see if the “IPsec” service is active with the following command:

# systemctl status ipsec
ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
   Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
   Active: inactive (dead)

If the “IPsec” service is active, check to see if any tunnels are configured in “/etc/ipsec.conf” and “/etc/ipsec.d/” with the following commands:

# grep -i conn /etc/ipsec.conf
conn mytunnel

# grep -i conn /etc/ipsec.d/*.conf
conn mytunnel

If there are indications that a “conn” parameter is configured for a tunnel, ask the System Administrator (SA) if the tunnel is documented with the ISSO. If “libreswan” is installed, “IPsec” is active, and an undocumented tunnel is active, this is a finding.'

# START_DESCRIBE RHEL-07-040830
  ipsec_exists = file('/etc/ipsec.conf').file?
  if ipsec_exists && service('ipsec').running?
    describe file('/etc/ipsec.conf') do
      its('content') { should_not match /^conn.*$/ }
    end

    describe command('grep -rE "^conn.*$" /etc/ipsec.d/*') do
      its('exit_status') { should eq 1 }
    end
  end
# STOP_DESCRIBE RHEL-07-040830

end

