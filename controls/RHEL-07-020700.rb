# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020700 - All files and directories contained in local interactive user home directories must have mode 0750 or less permissive.'
control 'RHEL-07-020700' do
  impact 0.5
  title 'All files and directories contained in local interactive user home directories must have mode 0750 or less permissive.'
  desc 'If a local interactive user files have excessive permissions, unintended users may be able to access or modify them.'
  tag 'stig', 'RHEL-07-020700'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020700_chk'
  tag fixid: 'F-RHEL-07-020700_fix'
  tag version: 'RHEL-07-020700'
  tag ruleid: 'RHEL-07-020700_rule'
  tag fixtext: 'Set the mode on files and directories in the local interactive user home directory with the following command:

# chmod 0750  /<home directory>/<users home directory>/<file>'
  tag checktext: 'Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of “0750”.

Check the mode of all non-initialization files in a local interactive user home directory with the following command:

Files that begin with a “.” are excluded from this requirement.

Note: The example will be for the user “smithj”, who has a home directory of “/home/smithj/home/smithj”

# ls -lLR /<home directory>/<users home directory>/
-rwxr-x--- 1 smithj smithj  18 Mar  5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r-x--- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with a mode more permissive than “0750”, this is a finding.'

# START_DESCRIBE RHEL-07-020700
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020700

end

