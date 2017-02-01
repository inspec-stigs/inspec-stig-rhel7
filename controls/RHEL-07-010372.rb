# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010372 - Accounts subject to three unsuccessful login attempts within 15 minutes must be locked for the maximum configurable period.'
control 'RHEL-07-010372' do
  impact 0.5
  title 'Accounts subject to three unsuccessful login attempts within 15 minutes must be locked for the maximum configurable period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.  Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005'
  tag 'stig', 'RHEL-07-010372'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010372_chk'
  tag fixid: 'F-RHEL-07-010372_fix'
  tag version: 'RHEL-07-010372'
  tag ruleid: 'RHEL-07-010372_rule'
  tag fixtext: 'Configure the operating system to lock an account for the maximum period when three unsuccessful logon attempts in 15 minutes are made.

Modify the first three lines of the auth section of the /etc/pam.d/system-auth and /etc/pam.d/password-auth files to match the following lines:

auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800
auth        sufficient     pam_unix.so try_first_pass
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800'
  tag checktext: 'Verify the operating system automatically locks an account for the maximum period for which the system can be configured.

Check that the system locks an account for the maximum period after three unsuccessful logon attempts within a period of 15 minutes with the following command:

# grep pam_faillock.so /etc/pam.d/password-auth
auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800

If the “unlock_time” setting is greater than 604800 on both lines with the pam_faillock.so module name or is missing from a line, this is a finding.'

# START_DESCRIBE RHEL-07-010372
  describe file('/etc/pam.d/password-auth') do
    its('content') { should match /^auth\s+required\s+pam_faillock\.so\s+preauth.*unlock_time=([0-9]|[1-8][0-9]|9[0-9]|[1-8][0-9]{2}|9[0-8][0-9]|99[0-9]|[1-8][0-9]{3}|9[0-8][0-9]{2}|99[0-8][0-9]|999[0-9]|[1-8][0-9]{4}|9[0-8][0-9]{3}|99[0-8][0-9]{2}|999[0-8][0-9]|9999[0-9]|[1-5][0-9]{5}|60[0-3][0-9]{3}|604[0-7][0-9]{2}|604800)(\s+.*)?$/ }
    its('content') { should match /^auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail.*unlock_time=([0-9]|[1-8][0-9]|9[0-9]|[1-8][0-9]{2}|9[0-8][0-9]|99[0-9]|[1-8][0-9]{3}|9[0-8][0-9]{2}|99[0-8][0-9]|999[0-9]|[1-8][0-9]{4}|9[0-8][0-9]{3}|99[0-8][0-9]{2}|999[0-8][0-9]|9999[0-9]|[1-5][0-9]{5}|60[0-3][0-9]{3}|604[0-7][0-9]{2}|604800)(\s+.*)?$/ }
  end
# STOP_DESCRIBE RHEL-07-010372

end

