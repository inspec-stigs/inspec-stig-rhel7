# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030310 - All privileged function executions must be audited.'
control 'RHEL-07-030310' do
  impact 0.5
  title 'All privileged function executions must be audited.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  tag 'stig', 'RHEL-07-030310'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030310_chk'
  tag fixid: 'F-RHEL-07-030310_fix'
  tag version: 'RHEL-07-030310'
  tag ruleid: 'RHEL-07-030310_rule'
  tag fixtext: 'Configure the operating system to audit the execution of privileged functions.

To find the relevant setuid/setgid programs, run the following command for each local partition [PART]:

# find [PART] -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null

For each setuid/setgid program on the system, which is not covered by an audit rule for a (sub) directory (such as /usr/sbin), add a line of the following form to "/etc/audit/rules.d/audit.rules", where <suid_prog_with_full_path> is the full path to each setuid/setgid program in the list:

a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid'
  tag checktext: 'Verify the operating system audits the execution of privileged functions.

To find relevant setuid and setgid programs, use the following command once for each local partition [PART]:

# find [PART] -xdev -local -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command:

#grep <suid_prog_with_full_path>
a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid

All setuid and setgid files on the system must have a corresponding audit rule, or must have an audit rule for the (sub) directory that contains the setuid/setgid file.

If all setuid/setgid files on the system do not have audit rule coverage, this is a finding.'

# START_DESCRIBE RHEL-07-030310
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030310

end

