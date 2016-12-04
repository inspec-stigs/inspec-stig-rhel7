# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010441 - The operating system must not allow users to override SSH environment variables.'
control 'RHEL-07-010441' do
  impact 0.5
  title 'The operating system must not allow users to override SSH environment variables.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  tag 'stig', 'RHEL-07-010441'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010441_chk'
  tag fixid: 'F-RHEL-07-010441_fix'
  tag version: 'RHEL-07-010441'
  tag ruleid: 'RHEL-07-010441_rule'
  tag fixtext: 'Configure the operating system to not allow users to override environment variables to the SSH daemon.

Edit the /etc/ssh/sshd_config file to uncomment or add the line for “PermitUserEnvironment” keyword and set the value to “no”:

PermitUserEnvironment no'
  tag checktext: 'Verify the operating system does not allow users to override environment variables to the SSH daemon.

Check for the value of the PermitUserEnvironment keyword with the following command:

# grep -i permituserenvironment /etc/ssh/sshd_config
PermitUserEnvironment no

If the “PermitUserEnvironment” keyword is not set to “no”, is missing, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-010441
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-010441

end

