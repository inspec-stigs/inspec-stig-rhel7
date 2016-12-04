# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040380 - The system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
control 'RHEL-07-040380' do
  impact 0.5
  title 'The system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  tag 'stig', 'RHEL-07-040380'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040380_chk'
  tag fixid: 'F-RHEL-07-040380_fix'
  tag version: 'RHEL-07-040380'
  tag ruleid: 'RHEL-07-040380_rule'
  tag fixtext: 'Set the system to the required kernel parameter with the following command:

# /sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1'
  tag checktext: 'Verify the system does not respond to IPv4 ICMP echoes sent to a broadcast address.

Check the value of the icmp_echo_ignore_broadcasts variable with the following command:

# /sbin/sysctl -a | grep  net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_echo_ignore_broadcasts=1

If the returned line does not have a value of “1”, a line is not returned, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040380
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040380

end

