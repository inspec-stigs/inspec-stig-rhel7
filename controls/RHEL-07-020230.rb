# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020230 - The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
control 'RHEL-07-020230' do
  impact 0.5
  title 'The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  tag 'stig', 'RHEL-07-020230'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020230_chk'
  tag fixid: 'F-RHEL-07-020230_fix'
  tag version: 'RHEL-07-020230'
  tag ruleid: 'RHEL-07-020230_rule'
  tag fixtext: 'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the line for the “UMASK” parameter in “/etc/login.defs” file to “077”:

UMASK  077'
  tag checktext: 'Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Check for the value of the “UMASK” parameter in “/etc/login.defs” file with the following command:

Note: If the value of the “UMASK” parameter is set to “000” in “/etc/login.defs” file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs
UMASK  077

If the value for the “UMASK” parameter is not “077”, or the “UMASK” parameter is missing or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-020230
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020230

end

