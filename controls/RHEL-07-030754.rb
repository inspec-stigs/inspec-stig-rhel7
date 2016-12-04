# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030754 - All uses of the unlinkat command must be audited.'
control 'RHEL-07-030754' do
  impact 0.5
  title 'All uses of the unlinkat command must be audited.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.  Satisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172'
  tag 'stig', 'RHEL-07-030754'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030754_chk'
  tag fixid: 'F-RHEL-07-030754_fix'
  tag version: 'RHEL-07-030754'
  tag ruleid: 'RHEL-07-030754_rule'
  tag fixtext: 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the unlinkat command occur.

Add the following rules to “/etc/audit/rules.d/audit.rules” (removing those that do not match the CPU architecture):

-a always,exit -F arch=b32 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete
-a always,exit -F arch=b64 -S unlinkat  -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the unlinkat command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i unlinkat/etc/audit/rules.d/audit.rules
-a always,exit -F arch=b32 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete
-a always,exit -F arch=b64 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete

If the command does not return any output, this is a finding.'

# START_DESCRIBE RHEL-07-030754
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030754

end

