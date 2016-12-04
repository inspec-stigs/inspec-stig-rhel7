# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020870 - All local interactive user initialization files executable search paths must contain only absolute paths.'
control 'RHEL-07-020870' do
  impact 0.5
  title 'All local interactive user initialization files executable search paths must contain only absolute paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user’s home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO).'
  tag 'stig', 'RHEL-07-020870'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020870_chk'
  tag fixid: 'F-RHEL-07-020870_fix'
  tag version: 'RHEL-07-020870'
  tag ruleid: 'RHEL-07-020870_rule'
  tag fixtext: 'Edit the local interactive user initialization files to change any PATH variable statements that reference directories other than their home directory. If a local interactive user requires path variables to reference a directory owned by the application, it must be documented with the ISSO.'
  tag checktext: 'Verify that all local interactive user initialization files path statements do not contain statements that will reference a working directory other than the users’ home directory.

Check the path statement for all local interactive user initialization files in the users\' home directory with the following commands:

Note: The example will be for the smithj user, which has a home directory of “/home/smithj”.

# grep -i path /home/smithj/.*
/home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin
/home/smithj/.bash_profile:export PATH

If any local interactive user initialization files have path statements that include directories outside of their home directory, this is a finding.'

# START_DESCRIBE RHEL-07-020870
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020870

end

