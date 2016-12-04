# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030351 - The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.'
control 'RHEL-07-030351' do
  impact 0.5
  title 'The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.'
  desc 'If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.'
  tag 'stig', 'RHEL-07-030351'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030351_chk'
  tag fixid: 'F-RHEL-07-030351_fix'
  tag version: 'RHEL-07-030351'
  tag ruleid: 'RHEL-07-030351_rule'
  tag fixtext: 'Configure the operating system to immediately notify the SA and ISSO (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.

Uncomment or edit the “space_left_action” keyword in /etc/audit/auditd.conf and set it to email. 
 
space_left_action = email'
  tag checktext: 'Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

Check what action the operating system takes when the threshold for the repository maximum audit record storage capacity is reached with the following command:

# grep -I space_left_action  /etc/audit/auditd.conf
space_left_action = email

If the value of the “space_left_action” keyword is not set to email, this is a finding.'

# START_DESCRIBE RHEL-07-030351
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030351

end

