# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010100 - When passwords are changed or new passwords are established, the new password must contain at least one lower-case character.'
control 'RHEL-07-010100' do
  impact 0.5
  title 'When passwords are changed or new passwords are established, the new password must contain at least one lower-case character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  tag 'stig', 'RHEL-07-010100'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010100_chk'
  tag fixid: 'F-RHEL-07-010100_fix'
  tag version: 'RHEL-07-010100'
  tag ruleid: 'RHEL-07-010100_rule'
  tag fixtext: 'Configure the operating system to enforce password complexity by requiring that at least one lower-case character be used by setting the “lcredit” option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

lcredit = -1'
  tag checktext: 'Note: The value to require a number of lower-case characters to be set is expressed as a negative number in /etc/security/pwquality.conf.

Check the value for "lcredit" in /etc/security/pwquality.conf with the following command:

# grep lcredit /etc/security/pwquality.conf
lcredit = -1

If the value of "lcredit" is not set to a negative value, this is a finding.'

# START_DESCRIBE RHEL-07-010100
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('lcredit') { should match /^-/ }
  end
# STOP_DESCRIBE RHEL-07-010100

end

