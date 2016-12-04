# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010220 - Passwords for new users must be restricted to a 60-day maximum lifetime.'
control 'RHEL-07-010220' do
  impact 0.5
  title 'Passwords for new users must be restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  tag 'stig', 'RHEL-07-010220'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010220_chk'
  tag fixid: 'F-RHEL-07-010220_fix'
  tag version: 'RHEL-07-010220'
  tag ruleid: 'RHEL-07-010220_rule'
  tag fixtext: 'Configure the operating system to enforce a 60-day maximum password lifetime restriction.

Add the following line in /etc/login.defs (or modify the line to have the required value):

PASS_MAX_DAYS     60'
  tag checktext: 'Verify the operating system enforces a 60-day maximum password lifetime restriction for new user accounts.

Check for the value of “PASS_MAX_DAYS” in /etc/login.defs with the following command:

# grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS     60

If the “PASS_MAX_DAYS” parameter value is not 60 or less, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-010220
  options = {
    assignment_re: /^(\w+)\s+(\w+?)$/
  }
  describe parse_config_file('/etc/login.defs', options) do
    its('PASS_MAX_DAYS') { should_not eq nil }
    its('PASS_MAX_DAYS') { should_not match /[6-9][1-9]|[7-9][0-9]/ }
  end
# STOP_DESCRIBE RHEL-07-010220

end

