# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021240 - A separate file system must be used for user home directories (such as /home or an equivalent).'
control 'RHEL-07-021240' do
  impact 0.1
  title 'A separate file system must be used for user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  tag 'stig', 'RHEL-07-021240'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-021240_chk'
  tag fixid: 'F-RHEL-07-021240_fix'
  tag version: 'RHEL-07-021240'
  tag ruleid: 'RHEL-07-021240_rule'
  tag fixtext: 'Migrate the /home directory onto a separate file system/partition.'
  tag checktext: 'Verify that a separate file system/partition has been created for non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users (those with a UID greater than 1000) on the system with the following command:

#cut -d: -f 1,3,6,7 /etc/passwd | egrep ":[1-4][0-9]{3}" | tr ":" "\t"

adamsj /home/adamsj /bin/bash
jacksonm /home/jacksonm /bin/bash
smithj /home/smithj /bin/bash

The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, /home) and users’ shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.

Check that a file system/partition has been created for the non-privileged interactive users with the following command:

Note: The partition of /home is used in the example.

# grep /home /etc/fstab
UUID=333ada18    /home                   ext4    noatime,nobarrier,nodev  1 2

If a separate entry for the file system/partition that contains the non-privileged interactive users\' home directories does not exist, or the file system/partition for the non-privileged interactive users is not /home, this is a finding.'

# START_DESCRIBE RHEL-07-021240
  describe file('/etc/fstab') do
    its('content') { should match /\/home/ }
  end
# STOP_DESCRIBE RHEL-07-021240

end

