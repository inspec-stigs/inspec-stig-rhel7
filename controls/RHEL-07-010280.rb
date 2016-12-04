# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010280 - The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.'
control 'RHEL-07-010280' do
  impact 0.5
  title 'The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.  Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.'
  tag 'stig', 'RHEL-07-010280'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010280_chk'
  tag fixid: 'F-RHEL-07-010280_fix'
  tag version: 'RHEL-07-010280'
  tag ruleid: 'RHEL-07-010280_rule'
  tag fixtext: 'Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) after the password expires.

Add the following line /etc/default/useradd (or modify the line to have the required value):

INACTIVE=0'
  tag checktext: 'Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires with the following command:

# grep -i inactive /etc/default/useradd
INACTIVE=0

If the value is not set to “0”, is commented out, or is not defined, this is a finding.'

# START_DESCRIBE RHEL-07-010280
  describe parse_config_file('/etc/default/useradd') do
    its('INACTIVE') { should eq '0' }
  end
# STOP_DESCRIBE RHEL-07-010280

end

