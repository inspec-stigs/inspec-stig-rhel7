# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010120 - When passwords are changed or new passwords are assigned, the new password must contain at least one special character.'
control 'RHEL-07-010120' do
  impact 0.5
  title 'When passwords are changed or new passwords are assigned, the new password must contain at least one special character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  tag 'stig', 'RHEL-07-010120'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010120_chk'
  tag fixid: 'F-RHEL-07-010120_fix'
  tag version: 'RHEL-07-010120'
  tag ruleid: 'RHEL-07-010120_rule'
  tag fixtext: 'Configure the operating system to enforce password complexity by requiring that at least one special character be used by setting the “dcredit” option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ocredit = -1'
  tag checktext: 'Verify the operating system enforces password complexity by requiring that at least one special character be used.

Note: The value to require a number of special characters to be set is expressed as a negative number in /etc/security/pwquality.conf.

Check the value for “ocredit” in /etc/security/pwquality.conf with the following command:

# grep ocredit /etc/security/pwquality.conf
ocredit=-1

If the value of “ocredit” is not set to a negative value, this is a finding.'

# START_DESCRIBE RHEL-07-010120
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('ocredit') { should match /^-/ }
  end
# STOP_DESCRIBE RHEL-07-010120

end

