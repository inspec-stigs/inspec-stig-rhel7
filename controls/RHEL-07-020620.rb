# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020620 - All local interactive users must have a home directory assigned in the /etc/passwd file.'
control 'RHEL-07-020620' do
  impact 0.5
  title 'All local interactive users must have a home directory assigned in the /etc/passwd file.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  tag 'stig', 'RHEL-07-020620'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020620_chk'
  tag fixid: 'F-RHEL-07-020620_fix'
  tag version: 'RHEL-07-020620'
  tag ruleid: 'RHEL-07-020620_rule'
  tag fixtext: 'Assign home directories to all local interactive users that currently do not have a home directory assigned.'
  tag checktext: 'Verify local interactive users on the system have a home directory assigned.

Check for missing local interactive user home directories with the following command:

# pwck -r
user \'lp\': directory \'/var/spool/lpd\' does not exist
user \'news\': directory \'/var/spool/news\' does not exist
user \'uucp\': directory \'/var/spool/uucp\' does not exist
user \'smithj\': directory \'/home/smithj\' does not exist

Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"

If any interactive users do not have a home directory assigned, this is a finding.'

# START_DESCRIBE RHEL-07-020620
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020620

end

