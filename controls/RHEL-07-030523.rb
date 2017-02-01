# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030523 - The operating system must generate audit records containing the full-text recording of modifications to sudo configuration files.'
control 'RHEL-07-030523' do
  impact 0.5
  title 'The operating system must generate audit records containing the full-text recording of modifications to sudo configuration files.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.  At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.  Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215'
  tag 'stig', 'RHEL-07-030523'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030523_chk'
  tag fixid: 'F-RHEL-07-030523_fix'
  tag version: 'RHEL-07-030523'
  tag ruleid: 'RHEL-07-030523_rule'
  tag fixtext: 'Configure the operating system to generate audit records containing the full-text recording of modifications to sudo configuration files. 

Add or update the following rule in /etc/audit/rules.d/audit.rules: 

-w /etc/sudoers -p wa -k privileged-actions

-w /etc/sudoers.d/ -p wa -k privileged-actions'
  tag checktext: 'Verify the operating system generates audit records containing the full-text recording of modifications to sudo configuration files. 

Check for modification of the following files being audited by performing the following commands to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /etc/sudoers /etc/audit/rules.d/audit.rules

-w /etc/sudoers -p wa -k privileged-actions

# grep -i /etc/sudoers.d/etc/audit/rules.d/audit.rules

-w /etc/sudoers.d/ -p wa -k privileged-actions

If the command does not return output that does not match the examples, this is a finding.'

# START_DESCRIBE RHEL-07-030523
  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /etc/sudoers.d/? -p wa -k privileged-actions}) }
  end
# STOP_DESCRIBE RHEL-07-030523

end
