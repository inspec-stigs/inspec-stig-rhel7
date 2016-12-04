# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020370 - All files and directories must have a valid group owner.'
control 'RHEL-07-020370' do
  impact 0.5
  title 'All files and directories must have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.'
  tag 'stig', 'RHEL-07-020370'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020370_chk'
  tag fixid: 'F-RHEL-07-020370_fix'
  tag version: 'RHEL-07-020370'
  tag ruleid: 'RHEL-07-020370_rule'
  tag fixtext: 'Either remove all files and directories from the system that do not have a valid group, or assign a valid group to all files and directories on the system with the chgrp command:

# chgrp <group> <file>'
  tag checktext: 'Verify all files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

# find / -fstype local -xdev -nogroup

If any files on the system do not have an assigned group, this is a finding.'

# START_DESCRIBE RHEL-07-020370
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020370

end

