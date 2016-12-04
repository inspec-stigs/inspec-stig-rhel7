# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010130 - When passwords are changed a minimum of eight of the total number of characters must be changed.'
control 'RHEL-07-010130' do
  impact 0.5
  title 'When passwords are changed a minimum of eight of the total number of characters must be changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  tag 'stig', 'RHEL-07-010130'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010130_chk'
  tag fixid: 'F-RHEL-07-010130_fix'
  tag version: 'RHEL-07-010130'
  tag ruleid: 'RHEL-07-010130_rule'
  tag fixtext: 'Configure the operating system to require the change of at least eight of the total number of characters when passwords are changed by setting the “difok” option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

difok = 8'
  tag checktext: 'The "difok" option sets the number of characters in a password that must not be present in the old password.

Check for the value of the difok option in /etc/security/pwquality.conf with the following command:

# grep difok /etc/security/pwquality.conf
difok = 8

If the value of “difok” is set to less than 8, this is a finding.'

# START_DESCRIBE RHEL-07-010130
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('difok') { should match /([8-9]|[1-9][0-9])/ }
  end
# STOP_DESCRIBE RHEL-07-010130

end

