# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010381 - Users must re-authenticate for privilege escalation.'
control 'RHEL-07-010381' do
  impact 0.5
  title 'Users must re-authenticate for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.   When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.  Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158'
  tag 'stig', 'RHEL-07-010381'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010381_chk'
  tag fixid: 'F-RHEL-07-010381_fix'
  tag version: 'RHEL-07-010381'
  tag ruleid: 'RHEL-07-010381_rule'
  tag fixtext: 'Configure the operating system to require users to reauthenticate for privilege escalation.

Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:

Remove any occurrences of "!authenticate" tags in the file.'
  tag checktext: 'Verify the operating system requires users to reauthenticate for privilege escalation.

Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:

# grep -i authenticate /etc/sudoers /etc/sudoers.d/*

If any line is found with a "!authenticate" tag, this is a finding.'

# START_DESCRIBE RHEL-07-010381
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-010381

end

