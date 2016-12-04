# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
system_users = attribute('system_users', default: [], description: 'list of known system users')
title 'RHEL-07-010210 - Passwords must be restricted to a 24 hours/1 day minimum lifetime.'
control 'RHEL-07-010210' do
  impact 0.5
  title 'Passwords must be restricted to a 24 hours/1 day minimum lifetime.'
  desc 'Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization\'s policy regarding password reuse.'
  tag 'stig', 'RHEL-07-010210'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010210_chk'
  tag fixid: 'F-RHEL-07-010210_fix'
  tag version: 'RHEL-07-010210'
  tag ruleid: 'RHEL-07-010210_rule'
  tag fixtext: 'Configure non-compliant accounts to enforce a 24 hours/1 day minimum password lifetime:

# chage -m 1 [user]'
  tag checktext: 'Check whether the minimum time period between password changes for each user account is one day or greater.

# awk -F: \'$4 < 1 {print $1}\' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.'

# START_DESCRIBE RHEL-07-010210
  if system_users.length > 0
    describe command("awk -F: '$4 < 1 {print $1}' /etc/shadow") do
      its('stdout') { should eq '' }
    end
  end
# STOP_DESCRIBE RHEL-07-010210

end

