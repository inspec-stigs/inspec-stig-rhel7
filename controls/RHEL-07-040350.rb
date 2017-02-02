# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040350 - The system must not forward Internet Protocol version 4 (IPv4) source-routed packets.'
control 'RHEL-07-040350' do
  impact 0.5
  title 'The system must not forward Internet Protocol version 4 (IPv4) source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  tag 'stig', 'RHEL-07-040350'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040350_chk'
  tag fixid: 'F-RHEL-07-040350_fix'
  tag version: 'RHEL-07-040350'
  tag ruleid: 'RHEL-07-040350_rule'
  tag fixtext: 'Set the system to the required kernel parameter by adding the following line to /etc/sysctl.conf (or modify the line to have the required value):

net.ipv4.conf.all.accept_source_route = 0'
  tag checktext: 'Verify the system does not accept IPv4 source-routed packets.

Check the value of the accept source route variable with the following command:

# /sbin/sysctl -a | grep  net.ipv4.conf.all.accept_source_route
net.ipv4.conf.all.accept_source_route=0

If the returned line does not have a value of “0”, a line is not returned, or the returned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040350
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
# STOP_DESCRIBE RHEL-07-040350

end

