# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010160 - When passwords are changed the number of repeating characters of the same character class must not be more than four characters.'
control 'RHEL-07-010160' do
  impact 0.5
  title 'When passwords are changed the number of repeating characters of the same character class must not be more than four characters.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  tag 'stig', 'RHEL-07-010160'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010160_chk'
  tag fixid: 'F-RHEL-07-010160_fix'
  tag version: 'RHEL-07-010160'
  tag ruleid: 'RHEL-07-010160_rule'
  tag fixtext: 'Configure the operating system to require the change of the number of repeating characters of the same character class when passwords are changed by setting the “maxclassrepeat” option.

Add the following line to /etc/security/pwquality.conf conf (or modify the line to have the required value):

maxclassrepeat = 4'
  tag checktext: 'The "maxclassrepeat" option sets the maximum number of allowed same consecutive characters in the same class in the new password.

Check for the value of the maxclassrepeat option in /etc/security/pwquality.conf with the following command:

# grep maxclassrepeat /etc/security/pwquality.conf
maxclassrepeat = 4

If the value of “maxclassrepeat” is set to more than 4, this is a finding.'

# START_DESCRIBE RHEL-07-010160
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('maxclassrepeat') { should match /([1-4])/ }
    its('maxclassrepeat') { should_not match /([5-9]|[1-9][0-9])/ }
  end
# STOP_DESCRIBE RHEL-07-010160

end

