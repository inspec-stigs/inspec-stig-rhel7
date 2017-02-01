# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010373 - If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked.'
control 'RHEL-07-010373' do
  impact 0.5
  title 'If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.  Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005'
  tag 'stig', 'RHEL-07-010373'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010373_chk'
  tag fixid: 'F-RHEL-07-010373_fix'
  tag version: 'RHEL-07-010373'
  tag ruleid: 'RHEL-07-010373_rule'
  tag fixtext: 'Configure the operating system to automatically lock the root account until the locked is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.

Modify the first three lines of the auth section of the /etc/pam.d/system-auth and /etc/pam.d/password-auth files to match the following lines:

auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800
auth        sufficient     pam_unix.so try_first_pass
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800'
  tag checktext: 'Verify the operating system automatically locks the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.

# grep pam_faillock.so /etc/pam.d/password-auth
auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900

If the “even_deny_root” setting is not defined on both lines with the pam_faillock.so module name, this is a finding.'

# START_DESCRIBE RHEL-07-010373
  describe file('/etc/pam.d/password-auth') do
    its('content') { should match /^auth\s+required\s+pam_faillock\.so\s+preauth.*even_deny_root.*$/ }
    its('content') { should match /^auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail.*even_deny_root.*$/ }
  end
# STOP_DESCRIBE RHEL-07-010373

end

