# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010442 - The operating system must not allow a non-certificate trusted host SSH logon to the system.'
control 'RHEL-07-010442' do
  impact 0.5
  title 'The operating system must not allow a non-certificate trusted host SSH logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  tag 'stig', 'RHEL-07-010442'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010442_chk'
  tag fixid: 'F-RHEL-07-010442_fix'
  tag version: 'RHEL-07-010442'
  tag ruleid: 'RHEL-07-010442_rule'
  tag fixtext: 'Configure the operating system to not allow a non-certificate trusted host SSH logon to the system.

Edit the /etc/ssh/sshd_config file to uncomment or add the line for “HostbasedAuthentication” keyword and set the value to “no”:

HostbasedAuthentication no'
  tag checktext: 'Verify the operating system does not allow a non-certificate trusted host SSH logon to the system.

Check for the value of the HostbasedAuthentication keyword with the following command:

# grep -i hostbasedauthentication /etc/ssh/sshd_config
HostbasedAuthentication no

If the “HostbasedAuthentication” keyword is not set to “no”, is missing, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-010442
  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
# STOP_DESCRIBE RHEL-07-010442

end

