# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010380 - Users must provide a password for privilege escalation.'
control 'RHEL-07-010380' do
  impact 0.5
  title 'Users must provide a password for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.   When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.  Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158'
  tag 'stig', 'RHEL-07-010380'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010380_chk'
  tag fixid: 'F-RHEL-07-010380_fix'
  tag version: 'RHEL-07-010380'
  tag ruleid: 'RHEL-07-010380_rule'
  tag fixtext: 'Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

Remove any occurrences of "NOPASSWD" tags in the file.'
  tag checktext: 'Verify the operating system requires users to supply a password for privilege escalation.

Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any line is found with a "NOPASSWD" tag, this is a finding.'

# START_DESCRIBE RHEL-07-010380
  sudoers_files = command('find /etc/sudoers* -type f 2> /dev/null').stdout.split("\n")
  sudoers_files.each do |sudoers_file|
    describe file(sudoers_file) do
      its('content') { should_not match /^(?!#).*(NOPASSWD|nopasswd).*$/ }
    end
  end
# STOP_DESCRIBE RHEL-07-010380

end
