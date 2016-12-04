# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021260 - The system must use /var/log/audit for the system audit data path.'
control 'RHEL-07-021260' do
  impact 0.1
  title 'The system must use /var/log/audit for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  tag 'stig', 'RHEL-07-021260'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-021260_chk'
  tag fixid: 'F-RHEL-07-021260_fix'
  tag version: 'RHEL-07-021260'
  tag ruleid: 'RHEL-07-021260_rule'
  tag fixtext: 'Migrate the system audit data path onto a separate file system.'
  tag checktext: 'Verify that a separate file system/partition has been created for the system audit data path.

Check that a file system/partition has been created for the system audit data path with the following command:

#grep /var/log/audit /etc/fstab
UUID=3645951a    /var/log/audit          ext4    defaults                 1 2

If a separate entry for /var/log/audit does not exist, ask the System Administrator (SA) if the system audit logs are being written to a different file system/partition on the system, then grep for that file system/partition. 

If a separate file system/partition does not exist for the system audit data path, this is a finding.'

# START_DESCRIBE RHEL-07-021260
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-021260

end

