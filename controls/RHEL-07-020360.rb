# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020360 - All files and directories must have a valid owner.'
control 'RHEL-07-020360' do
  impact 0.5
  title 'All files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier “UID” as the UID of the un-owned files.'
  tag 'stig', 'RHEL-07-020360'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020360_chk'
  tag fixid: 'F-RHEL-07-020360_fix'
  tag version: 'RHEL-07-020360'
  tag ruleid: 'RHEL-07-020360_rule'
  tag fixtext: 'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on the system with the chown command:

# chown <user> <file>'
  tag checktext: 'Verify all files and directories on the system have a valid owner.

Check the owner of all files and directories with the following command:

# find / -fstype local -xdev -nouser

If any files on the system do not have an assigned owner, this is a finding.'

# START_DESCRIBE RHEL-07-020360
  describe command('find / -xdev -nouser -fstype local 2> /dev/null') do
    its('stdout') { should eq '' }
  end
# STOP_DESCRIBE RHEL-07-020360

end

