# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010200 - Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime.'
control 'RHEL-07-010200' do
  impact 0.5
  title 'Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime.'
  desc 'Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization\'s policy regarding password reuse.'
  tag 'stig', 'RHEL-07-010200'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010200_chk'
  tag fixid: 'F-RHEL-07-010200_fix'
  tag version: 'RHEL-07-010200'
  tag ruleid: 'RHEL-07-010200_rule'
  tag fixtext: 'Configure the operating system to enforce 24 hours/1 day as the minimum password lifetime.

Add the following line in /etc/login.defs (or modify the line to have the required value):

PASS_MIN_DAYS     1'
  tag checktext: 'Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts.

Check for the value of “PASS_MIN_DAYS” in /etc/login.defs with the following command:

# grep -i pass_min_days /etc/login.defs
PASS_MIN_DAYS     1

If the “PASS_MIN_DAYS” parameter value is not “1” or greater, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-010200
  options = {
    assignment_regex: /^(\w+)\s+(\w+?)$/
  }
  describe parse_config_file('/etc/login.defs', options) do
    its('PASS_MIN_DAYS') { should match /[1-9]|[0-9][1-9]/ }
  end
# STOP_DESCRIBE RHEL-07-010200

end

