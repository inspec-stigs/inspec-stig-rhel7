# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030510 - All uses of the passwd command must be audited.'
control 'RHEL-07-030510' do
  impact 0.5
  title 'All uses of the passwd command must be audited.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.  At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.  Satisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215'
  tag 'stig', 'RHEL-07-030510'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030510_chk'
  tag fixid: 'F-RHEL-07-030510_fix'
  tag version: 'RHEL-07-030510'
  tag ruleid: 'RHEL-07-030510_rule'
  tag fixtext: 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the “passwd” command occur.

Add or update the following rule in /etc/audit/rules.d/audit.rules:

-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-passwd

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the “passwd” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/bin/passwd /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-passwd

If the command does not return any output, this is a finding.'

# START_DESCRIBE RHEL-07-030510
  describe auditd_rules.syscall('all').path('/usr/bin/passwd').perm('x').key('privileged-passwd').action('always').list do
    it { should eq(['exit']) }
  end
# STOP_DESCRIBE RHEL-07-030510

end

