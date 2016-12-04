# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040410 - The system must ignore to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.'
control 'RHEL-07-040410' do
  impact 0.5
  title 'The system must ignore to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.'
  desc 'ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host\'s route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.'
  tag 'stig', 'RHEL-07-040410'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040410_chk'
  tag fixid: 'F-RHEL-07-040410_fix'
  tag version: 'RHEL-07-040410'
  tag ruleid: 'RHEL-07-040410_rule'
  tag fixtext: 'Set the system to the required kernel parameter by adding the following line to /etc/sysctl.conf (or modify the line to have the required value):

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0'
  tag checktext: 'Verify the system ignores IPv4 ICMP redirect messages.

Check the value of the “accept_redirects” variables with the following command:

# /sbin/sysctl -a | grep  \'net.ipv4.conf.*.accept_redirects\'
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0

If both of the returned line do not have a value of “0”, a line is not returned, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040410
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040410

end

