# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030630 - All uses of the pam_timestamp_check command must be audited.'
control 'RHEL-07-030630' do
  impact 0.5
  title 'All uses of the pam_timestamp_check command must be audited.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  tag 'stig', 'RHEL-07-030630'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030630_chk'
  tag fixid: 'F-RHEL-07-030630_fix'
  tag version: 'RHEL-07-030630'
  tag ruleid: 'RHEL-07-030630_rule'
  tag fixtext: 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the pam_timestamp_check command occur. 

Add or update the following rule in /etc/audit/rules.d/audit.rules: 

-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-pam

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the pam_timestamp_check command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /sbin/pam_timestamp_check /etc/audit/rules.d/audit.rules

-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295  -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-pam  

If the command does not return any output, this is a finding.'

# START_DESCRIBE RHEL-07-030630
  describe auditd_rules.syscall('all').path('/sbin/pam_timestamp_check').action do
    it { should eq(['always']) }
  end
# STOP_DESCRIBE RHEL-07-030630

end

