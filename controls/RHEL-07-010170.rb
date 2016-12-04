# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010170 - The PAM system service must be configured to store only encrypted representations of passwords.'
control 'RHEL-07-010170' do
  impact 0.5
  title 'The PAM system service must be configured to store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.'
  tag 'stig', 'RHEL-07-010170'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010170_chk'
  tag fixid: 'F-RHEL-07-010170_fix'
  tag version: 'RHEL-07-010170'
  tag ruleid: 'RHEL-07-010170_rule'
  tag fixtext: 'Configure the operating system to store only SHA512 encrypted representations of passwords.

Add the following line in /etc/pam.d/system-auth:

password sufficient pam_unix.so sha512'
  tag checktext: 'Verify the PAM system service is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the following command:

# grep password /etc/pam.d/system-auth
password sufficient pam_unix.so sha512

If the /etc/pam.d/system-auth configuration files allow for password hashes other than SHA512 to be used, this is a finding.'

# START_DESCRIBE RHEL-07-010170
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /password\s+sufficient\s+pam_unix.so\s+sha512/ }
  end
# STOP_DESCRIBE RHEL-07-010170

end

