# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010270 - The SSH daemon must not allow authentication using an empty password.'
control 'RHEL-07-010270' do
  impact 1.0
  title 'The SSH daemon must not allow authentication using an empty password.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  tag 'stig', 'RHEL-07-010270'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010270_chk'
  tag fixid: 'F-RHEL-07-010270_fix'
  tag version: 'RHEL-07-010270'
  tag ruleid: 'RHEL-07-010270_rule'
  tag fixtext: 'To explicitly disallow remote logon from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config":

PermitEmptyPasswords no

Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.'
  tag checktext: 'To determine how the SSH daemon\'s "PermitEmptyPasswords" option is set, run the following command:

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, the required value is set.

If the required value is not set, this is a finding.'

# START_DESCRIBE RHEL-07-010270
  describe parse_config_file('/etc/ssh/sshd_config') do
    its('PermitEmptyPasswords') { should_not eq "yes" }
  end
# STOP_DESCRIBE RHEL-07-010270

end

