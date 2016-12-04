# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040860 - The system must not forward IPv6 source-routed packets.'
control 'RHEL-07-040860' do
  impact 0.5
  title 'The system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  tag 'stig', 'RHEL-07-040860'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040860_chk'
  tag fixid: 'F-RHEL-07-040860_fix'
  tag version: 'RHEL-07-040860'
  tag ruleid: 'RHEL-07-040860_rule'
  tag fixtext: 'Set the system to the required kernel parameter, if IPv6 is enabled, by adding the following line to /etc/sysctl.conf (or modify the line to have the required value):

net.ipv6.conf.all.accept_source_route = 0'
  tag checktext: 'Verify the system does not accept IPv6 source-routed packets.

Note: If IPv6 is not enabled, the key will not exist, and this is not a finding.

Check the value of the accept source route variable with the following command:

# /sbin/sysctl -a | grep  net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route=0

If the returned lines do not have a value of “0”, a line is not returned, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040860
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040860

end

