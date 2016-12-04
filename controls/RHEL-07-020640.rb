# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020640 - All local interactive user home directories defined in the /etc/passwd file must exist.'
control 'RHEL-07-020640' do
  impact 0.5
  title 'All local interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.'
  tag 'stig', 'RHEL-07-020640'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020640_chk'
  tag fixid: 'F-RHEL-07-020640_fix'
  tag version: 'RHEL-07-020640'
  tag ruleid: 'RHEL-07-020640_rule'
  tag fixtext: 'Create home directories to all local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in “/etc/ passwd”:

Note: The example will be for the user smithj, who has a home directory of “/home/smithj”, a UID of “smithj”, and a Group Identifier (GID) of “users assigned” in “/etc/passwd”.

# mkdir /home/smithj 
# chown smithj /home/smithj
# chgrp users /home/smithj
# chmod 0750 /home/smithj'
  tag checktext: 'Verify the assigned home directory of all local interactive users on the system exists.

Check the home directory assignment for all local interactive non-privileged users on the system with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-9][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj

Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check that all referenced home directories exist with the following command:

# pwck -r
user \'smithj\': directory \'/home/smithj\' does not exist

If any home directories referenced in “/etc/passwd” are returned as not defined, this is a finding.'

# START_DESCRIBE RHEL-07-020640
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020640

end

