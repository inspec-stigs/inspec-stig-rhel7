# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021060 - The umask must be set to 077 for all local interactive user accounts.'
control 'RHEL-07-021060' do
  impact 0.5
  title 'The umask must be set to 077 for all local interactive user accounts.'
  desc 'The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 700 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be “0”. This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.'
  tag 'stig', 'RHEL-07-021060'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021060_chk'
  tag fixid: 'F-RHEL-07-021060_fix'
  tag version: 'RHEL-07-021060'
  tag ruleid: 'RHEL-07-021060_rule'
  tag fixtext: 'Remove the umask statement from all local interactive users’ initialization files. 

If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the Information System Security Manager (ISSM), but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account’s environment variables.'
  tag checktext: 'Verify that the default umask for all local interactive users is “077”.

Identify the locations of all local interactive user home directories by looking at the “/etc/passwd” file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the /home directory.

# grep -i umask /home/*/.*

If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than “077”, this is a finding.'

# START_DESCRIBE RHEL-07-021060
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-021060

end

