# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020880 - Local initialization files must not execute world-writable programs.'
control 'RHEL-07-020880' do
  impact 0.5
  title 'Local initialization files must not execute world-writable programs.'
  desc 'If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.'
  tag 'stig', 'RHEL-07-020880'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020880_chk'
  tag fixid: 'F-RHEL-07-020880_fix'
  tag version: 'RHEL-07-020880'
  tag ruleid: 'RHEL-07-020880_rule'
  tag fixtext: 'Set the mode on files being executed by the local initialization files with the following command:

# chmod 0755  <file>'
  tag checktext: 'Verify that local initialization files do not execute world-writable programs.

Check the system for world-writable files with the following command:
# find / -perm -002 -type f -exec ls -ld {} \; | more

For all files listed, check for their presence in the local initialization files with the following commands:

Note: The example will be for a system that is configured to create users’ home directories in the /home directory.

# grep <file> /home/*/.*

If any local initialization files are found to reference world-writable files, this is a finding.'

# START_DESCRIBE RHEL-07-020880
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020880

end

