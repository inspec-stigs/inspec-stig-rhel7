# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010140 - When passwords are changed a minimum of four character classes must be changed.'
control 'RHEL-07-010140' do
  impact 0.5
  title 'When passwords are changed a minimum of four character classes must be changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  tag 'stig', 'RHEL-07-010140'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010140_chk'
  tag fixid: 'F-RHEL-07-010140_fix'
  tag version: 'RHEL-07-010140'
  tag ruleid: 'RHEL-07-010140_rule'
  tag fixtext: 'Configure the operating system to require the change of at least four character classes when passwords are changed by setting the “minclass” option.

Add the following line to /etc/security/pwquality.conf conf (or modify the line to have the required value):

minclass = 4'
  tag checktext: 'The "minclass" option sets the minimum number of required classes of characters for the new password (digits, uppercase, lowercase, others).

Check for the value of the “minclass” option in /etc/security/pwquality.conf with the following command:

# grep minclass /etc/security/pwquality.conf
minclass = 4

If the value of “minclass” is set to less than 4, this is a finding.'

# START_DESCRIBE RHEL-07-010140
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('minclass') { should match /([4-9]|[1-9][0-9])/ }
  end
# STOP_DESCRIBE RHEL-07-010140

end

