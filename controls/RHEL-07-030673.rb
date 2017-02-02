# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030673 - All uses of the rmmod command must be audited.'
control 'RHEL-07-030673' do
  impact 0.5
  title 'All uses of the rmmod command must be audited.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.   Audit records can be generated from various components within the information system (e.g., module or policy filter).  Satisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222'
  tag 'stig', 'RHEL-07-030673'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030673_chk'
  tag fixid: 'F-RHEL-07-030673_fix'
  tag version: 'RHEL-07-030673'
  tag ruleid: 'RHEL-07-030673_rule'
  tag fixtext: 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the rmmod command occur. 

Add or update the following rule to /etc/audit/rules.d/audit.rules (removing those that do not match the CPU architecture): 

-w /sbin/rmmod-p x -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the rmmod command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

# grep -i rmmod /etc/audit/etc/audit/rules.d/audit.rules

If the command does not return the following output (appropriate to the architecture), this is a finding. 

-w /sbin/rmmod -p x -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

If the command does not return any output, this is a finding.'

# START_DESCRIBE RHEL-07-030673
  # These -w should be -a always,exit
  describe auditd_rules.syscall('all').path('/sbin/rmmod').perm('x').key('module-change').action('always').list do
    it { should eq(['exit']) }
  end
# STOP_DESCRIBE RHEL-07-030673

end

