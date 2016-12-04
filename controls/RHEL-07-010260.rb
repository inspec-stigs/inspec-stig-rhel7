# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010260 - The system must not have accounts configured with blank or null passwords.'
control 'RHEL-07-010260' do
  impact 1.0
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  tag 'stig', 'RHEL-07-010260'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010260_chk'
  tag fixid: 'F-RHEL-07-010260_fix'
  tag version: 'RHEL-07-010260'
  tag ruleid: 'RHEL-07-010260_rule'
  tag fixtext: 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authenticating.

Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" to prevent logons with empty passwords.'
  tag checktext: 'To verify that null passwords cannot be used, run the following command:

# grep nullok /etc/pam.d/system-auth

If this produces any output, it may be possible to log on with accounts with empty passwords.

If null passwords can be used, this is a finding.'

# START_DESCRIBE RHEL-07-010260
  describe file('/etc/pam.d/system-auth') do
    its('content') { should_not match /nullok/ }
  end
# STOP_DESCRIBE RHEL-07-010260

end

