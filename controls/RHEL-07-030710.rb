# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030710 - The operating system must generate audit records for all account creations, modifications, disabling, and termination events.'
control 'RHEL-07-030710' do
  impact 0.5
  title 'The operating system must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  Audit records can be generated from various components within the information system (e.g., module or policy filter).  Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000241-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221'
  tag 'stig', 'RHEL-07-030710'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030710_chk'
  tag fixid: 'F-RHEL-07-030710_fix'
  tag version: 'RHEL-07-030710'
  tag ruleid: 'RHEL-07-030710_rule'
  tag fixtext: 'Configure the operating system to generate audit records for all account creations, modifications, disabling, and termination events.

Add or update the following file system rules to /etc/audit/rules.d/audit.rules:

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system automatically audits account creation by performing the following series of commands to check the file system rules in /etc/audit/rules.d/audit.rules:

# grep /etc/group /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/group -p wa -k audit_rules_usergroup_modification

# grep /etc/passwd /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/passwd -p wa -k audit_rules_usergroup_modification

# grep /etc/gshadow /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/gshadow -p wa -k audit_rules_usergroup_modification

# grep /etc/shadow /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/shadow -p wa -k audit_rules_usergroup_modification

# grep /etc/security/opasswd /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification'

# START_DESCRIBE RHEL-07-030710
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030710

end

