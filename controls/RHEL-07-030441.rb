# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030441 - All uses of the semanage command must be audited.'
control 'RHEL-07-030441' do
  impact 0.5
  title 'All uses of the semanage command must be audited.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  Audit records can be generated from various components within the information system (e.g., module or policy filter).  Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207, SRG-OS-000465-GPOS-00209'
  tag 'stig', 'RHEL-07-030441'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030441_chk'
  tag fixid: 'F-RHEL-07-030441_fix'
  tag version: 'RHEL-07-030441'
  tag ruleid: 'RHEL-07-030441_rule'
  tag fixtext: 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the semanage command occur.

Add or update the following rule in /etc/audit/rules.d/audit.rules:

-a always,exit -F path=/usr/sbin/semanage
-F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the “semanage” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/sbin/semanage /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding.

-a always,exit -F path=/usr/sbin/semanage
-F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change'

# START_DESCRIBE RHEL-07-030441
  describe auditd_rules.syscall('all').path('/usr/sbin/semanage').action do
    it { should eq(['always']) }
  end
# STOP_DESCRIBE RHEL-07-030441

end

