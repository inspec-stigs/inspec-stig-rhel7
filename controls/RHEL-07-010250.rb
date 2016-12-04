# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010250 - Passwords must be a minimum of 15 characters in length.'
control 'RHEL-07-010250' do
  impact 0.5
  title 'Passwords must be a minimum of 15 characters in length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.  Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  tag 'stig', 'RHEL-07-010250'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010250_chk'
  tag fixid: 'F-RHEL-07-010250_fix'
  tag version: 'RHEL-07-010250'
  tag ruleid: 'RHEL-07-010250_rule'
  tag fixtext: 'Configure operating system to enforce a minimum 15-character password length.

Add the following line to /etc/security/pwquality.conf conf (or modify the line to have the required value):

minlen = 15'
  tag checktext: 'Verify the operating system enforces a minimum 15-character password length. The “minlen” option sets the minimum number of characters in a new password.

Check for the value of the “minlen” option in /etc/security/pwquality.conf with the following command:

# grep minlen /etc/security/pwquality.conf
minlen = 15

If the command does not return a “minlen” value of 15 or greater, this is a finding.'

# START_DESCRIBE RHEL-07-010250
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('minlen') { should_not match /^\d$|^1[0-4]$/ }
    its('minlen') { should_not eq nil }
  end
# STOP_DESCRIBE RHEL-07-010250

end

