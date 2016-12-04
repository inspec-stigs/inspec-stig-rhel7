# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040730 - The system must not be performing packet forwarding unless the system is a router.'
control 'RHEL-07-040730' do
  impact 0.5
  title 'The system must not be performing packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  tag 'stig', 'RHEL-07-040730'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040730_chk'
  tag fixid: 'F-RHEL-07-040730_fix'
  tag version: 'RHEL-07-040730'
  tag ruleid: 'RHEL-07-040730_rule'
  tag fixtext: 'Set the system to the required kernel parameter by adding the following line to /etc/sysctl.conf (or modify the line to have the required value):

net.ipv4.ip_forward = 0'
  tag checktext: 'Verify the system is not performing packet forwarding, unless the system is a router.

Check to see if IP forwarding is enabled using the following command:

# /sbin/sysctl -a | grep  net.ipv4.ip_forward
net.ipv4.ip_forward=0

If IP forwarding value is “1” and the system is hosting any application, database, or web servers, this is a finding.'

# START_DESCRIBE RHEL-07-040730
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040730

end

