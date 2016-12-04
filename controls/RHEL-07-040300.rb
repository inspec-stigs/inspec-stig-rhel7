# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040300 - The system must display the date and time of the last successful account logon upon logon.'
control 'RHEL-07-040300' do
  impact 0.1
  title 'The system must display the date and time of the last successful account logon upon logon.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  tag 'stig', 'RHEL-07-040300'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-040300_chk'
  tag fixid: 'F-RHEL-07-040300_fix'
  tag version: 'RHEL-07-040300'
  tag ruleid: 'RHEL-07-040300_rule'
  tag fixtext: 'Configure the operating system to provide users with feedback on when account accesses last occurred by setting the required configuration options in “/etc/pam.d/postlogin”. 

Add the following line to the top of “/etc/pam.d/postlogin”:

session     required      pam_lastlog.so showfailed'
  tag checktext: 'Verify that users are provided with feedback on when account accesses last occurred.

Check that “pam_lastlog” is used and not silent with the following command:

# grep pam_lastlog /etc/pam.d/postlogin

session     required      pam_lastlog.so showfailed silent

If “pam_lastlog” is missing from “/etc/pam.d/postlogin” file, or the silent option is present on the line check for the “PrintLastLog” keyword in the sshd daemon configuration file, this is a finding.'

# START_DESCRIBE RHEL-07-040300
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040300

end

