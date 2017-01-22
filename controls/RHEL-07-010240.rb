# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010240 - Passwords must be prohibited from reuse for a minimum of five generations.'
control 'RHEL-07-010240' do
  impact 0.5
  title 'Passwords must be prohibited from reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.'
  tag 'stig', 'RHEL-07-010240'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010240_chk'
  tag fixid: 'F-RHEL-07-010240_fix'
  tag version: 'RHEL-07-010240'
  tag ruleid: 'RHEL-07-010240_rule'
  tag fixtext: 'Configure the operating system to prohibit password reuse for a minimum of five generations.

Add the following line in /etc/pam.d/system-auth (or modify the line to have the required value):

password sufficient pam_unix.so use_authtok sha512 shadow remember=5'
  tag checktext: 'Verify the operating system prohibits password reuse for a minimum of five generations.

Check for the value of the “remember” argument in /etc/pam.d/system-auth with the following command:

# grep -i remember /etc/pam.d/system-auth
password sufficient pam_unix.so use_authtok sha512 shadow remember=5

If the line containing the pam_unix.so line does not have the “remember” module argument set, or the value of the “remember” module argument is set to less than “5”, this is a finding.'

# START_DESCRIBE RHEL-07-010240
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /^password\s+sufficient\s+pam_unix\.so.+??remember=([5-9]|[1-9][0-9])/ }
  end
# STOP_DESCRIBE RHEL-07-010240

end
