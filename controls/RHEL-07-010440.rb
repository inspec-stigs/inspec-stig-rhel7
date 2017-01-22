# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010440 - The operating system must not allow empty passwords for SSH logon to the system.'
control 'RHEL-07-010440' do
  impact 1.0
  title 'The operating system must not allow empty passwords for SSH logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  tag 'stig', 'RHEL-07-010440'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010440_chk'
  tag fixid: 'F-RHEL-07-010440_fix'
  tag version: 'RHEL-07-010440'
  tag ruleid: 'RHEL-07-010440_rule'
  tag fixtext: 'Configure the operating system to not allow empty passwords for SSH logon to the system.

Edit the /etc/ssh/sshd_config file to uncomment or add the line for “PermitEmptyPasswords” keyword and set the value to “no”:

PermitEmptyPasswords no'
  tag checktext: 'Verify the operating system does not allow empty passwords to be used for SSH logon to the system.

Check for the value of the PermitEmptyPasswords keyword with the following command:

# grep -i permitemptypassword /etc/ssh/sshd_config
PermitEmptyPasswords no

If the “PermitEmptyPasswords” keyword is not set to “no”, is missing, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-010440
  describe sshd_config do
    its('PermitEmptyPasswords') { should eq 'no' }
  end
# STOP_DESCRIBE RHEL-07-010440

end

