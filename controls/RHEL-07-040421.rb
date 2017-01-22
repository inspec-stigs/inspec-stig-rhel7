# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040421 - The system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects.'
control 'RHEL-07-040421' do
  impact 0.5
  title 'The system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects.'
  desc 'ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system\'s route table, possibly revealing portions of the network topology.'
  tag 'stig', 'RHEL-07-040421'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040421_chk'
  tag fixid: 'F-RHEL-07-040421_fix'
  tag version: 'RHEL-07-040421'
  tag ruleid: 'RHEL-07-040421_rule'
  tag fixtext: 'Configure the system to not allow interfaces to perform IPv4 ICMP redirects. 

Set the system to the required kernel parameter by adding the following line to /etc/sysctl.conf (or modify the line to have the required value):

net.ipv4.conf.all.send_redirects=0'
  tag checktext: 'Verify the system does not send IPv4 ICMP redirect messages.

Check the value of the "all send_redirects" variables with the following command:

# /sbin/sysctl -a | grep  net.ipv4.conf.all.send_redirects

net.ipv4.conf.all.send_redirects=0

If the returned line does not have a value of “0”, a line is not returned, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040421
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
# STOP_DESCRIBE RHEL-07-040421

end

