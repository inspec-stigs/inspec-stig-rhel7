# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030352 - The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.'
control 'RHEL-07-030352' do
  impact 0.5
  title 'The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.'
  desc 'If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.'
  tag 'stig', 'RHEL-07-030352'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030352_chk'
  tag fixid: 'F-RHEL-07-030352_fix'
  tag version: 'RHEL-07-030352'
  tag ruleid: 'RHEL-07-030352_rule'
  tag fixtext: 'Configure the operating system to immediately notify the SA and ISSO (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.

Uncomment or edit the action_mail_acct keyword in /etc/audit/auditd.conf and set it to root and any other accounts associated with security personnel. 
 
action_mail_acct = root'
  tag checktext: 'Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.

Check what account the operating system emails when the threshold for the repository maximum audit record storage capacity is reached with the following command:

# grep -i action_mail_acct  /etc/audit/auditd.conf
action_mail_acct = root

If the value of the “action_mail_acct” keyword is not set to “root” and other accounts for security personnel, this is a finding.'

# START_DESCRIBE RHEL-07-030352
  describe auditd_conf do
    its('action_mail_acct') { should eq 'root' }
  end
# STOP_DESCRIBE RHEL-07-030352

end

