# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040470 - Network interfaces must not be in promiscuous mode.'
control 'RHEL-07-040470' do
  impact 0.5
  title 'Network interfaces must not be in promiscuous mode.'
  desc 'Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow then to collect information such as logon IDs, passwords, and key exchanges between systems.  If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Manager (ISSM) and restricted to only authorized personnel.'
  tag 'stig', 'RHEL-07-040470'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040470_chk'
  tag fixid: 'F-RHEL-07-040470_fix'
  tag version: 'RHEL-07-040470'
  tag ruleid: 'RHEL-07-040470_rule'
  tag fixtext: 'Configure network interfaces to turn off promiscuous mode unless approved by the ISSM and documented.

Set the promiscuous mode of an interface to off with the following command:

#ip link set dev <devicename> multicast off promisc off'
  tag checktext: 'Verify network interfaces are not in promiscuous mode unless approved by the Information System Security Manager (ISSM) and documented.

Check for the status with the following command:

# ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSM and documented, this is a finding.'

# START_DESCRIBE RHEL-07-040470
  describe command('ip link | grep -i promisc') do
    its('stdout') { should match /^$/ }
    its('exit_status') { should eq 1 }
  end
# STOP_DESCRIBE RHEL-07-040470

end

