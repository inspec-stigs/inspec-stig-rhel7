# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021250 - The system must use a separate file system for /var.'
control 'RHEL-07-021250' do
  impact 0.1
  title 'The system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  tag 'stig', 'RHEL-07-021250'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-021250_chk'
  tag fixid: 'F-RHEL-07-021250_fix'
  tag version: 'RHEL-07-021250'
  tag ruleid: 'RHEL-07-021250_rule'
  tag fixtext: 'Migrate the /var path onto a separate file system.'
  tag checktext: 'Verify that a separate file system/partition has been created for /var.

Check that a file system/partition has been created for /var with the following command:

# grep /var /etc/fstab
UUID=c274f65f    /var                    ext4    noatime,nobarrier        1 2

If a separate entry for /var is not in use, this is a finding.'

# START_DESCRIBE RHEL-07-021250
  describe file('/etc/fstab') do
    its('content') { should match /\/var/ }
  end
# STOP_DESCRIBE RHEL-07-021250

end

