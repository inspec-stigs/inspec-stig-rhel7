# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030492 - The operating system must generate audit records for all successful account access events.'
control 'RHEL-07-030492' do
  impact 0.5
  title 'The operating system must generate audit records for all successful account access events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  Audit records can be generated from various components within the information system (e.g., module or policy filter).  Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218'
  tag 'stig', 'RHEL-07-030492'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030492_chk'
  tag fixid: 'F-RHEL-07-030492_fix'
  tag version: 'RHEL-07-030492'
  tag ruleid: 'RHEL-07-030492_rule'
  tag fixtext: 'Configure the operating system to generate audit records when successful account access events occur. 

Add or update the following rule in /etc/audit/rules.d/audit.rules: 

-w /var/log/lastlog -p wa -k logins

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system generates audit records when successful account access events occur. 

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands: 

# grep -i /var/log/lastlog etc/audit/audit.rules

-w /var/log/lastlog -p wa -k logins 

If the command does not return any output, this is a finding.'

# START_DESCRIBE RHEL-07-030492
  describe auditd_rules do
    its('lines') { should include('-w /var/log/lastlog -p wa -k logins') }
  end
# STOP_DESCRIBE RHEL-07-030492

end

