# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030674 - All uses of the modprobe command must be audited.'
control 'RHEL-07-030674' do
  impact 0.5
  title 'All uses of the modprobe command must be audited.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.   Audit records can be generated from various components within the information system (e.g., module or policy filter).  Satisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222'
  tag 'stig', 'RHEL-07-030674'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030674_chk'
  tag fixid: 'F-RHEL-07-030674_fix'
  tag version: 'RHEL-07-030674'
  tag ruleid: 'RHEL-07-030674_rule'
  tag fixtext: 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the modprobe command occur. 

Add or update the following rule to /etc/audit/rules.d/audit.rules (removing those that do not match the CPU architecture): 

-w /sbin/modprobe -p x -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the modprobe command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the line appropriate for the system architecture must be present.

# grep -i modprobe /etc/audit/etc/audit/rules.d/audit.rules

If the command does not return the following output (appropriate to the architecture), this is a finding. 

-w /sbin/modprobe -p x -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

If the command does not return any output, this is a finding.'

# START_DESCRIBE RHEL-07-030674
  # These -w should be -a always,exit
  describe auditd_rules.syscall('all').path('/sbin/modprobe').perm('x').key('module-change').action('always').list do
    it { should eq(['exit']) }
  end
# STOP_DESCRIBE RHEL-07-030674

end

