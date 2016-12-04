# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
system_users = attribute('system_users', default: [], description: 'list of known system users')
title 'RHEL-07-010230 - Existing passwords must be restricted to a 60-day maximum lifetime.'
control 'RHEL-07-010230' do
  impact 0.5
  title 'Existing passwords must be restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  tag 'stig', 'RHEL-07-010230'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010230_chk'
  tag fixid: 'F-RHEL-07-010230_fix'
  tag version: 'RHEL-07-010230'
  tag ruleid: 'RHEL-07-010230_rule'
  tag fixtext: 'Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction.

# chage -M 60 [user]'
  tag checktext: 'Check whether the maximum time period for existing passwords is restricted to 60 days.

# awk -F: \'$5 > 60 {print $1}\' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.'

# START_DESCRIBE RHEL-07-010230
  if system_users.length > 0
    describe command("awk -F: '$5 > 60 {print $1}' /etc/shadow") do
      its('stdout') { should eq '' }
    end
  end
# STOP_DESCRIBE RHEL-07-010230

end

