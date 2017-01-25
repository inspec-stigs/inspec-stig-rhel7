# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030350 - The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.'
control 'RHEL-07-030350' do
  impact 0.5
  title 'The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  tag 'stig', 'RHEL-07-030350'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030350_chk'
  tag fixid: 'F-RHEL-07-030350_fix'
  tag version: 'RHEL-07-030350'
  tag ruleid: 'RHEL-07-030350_rule'
  tag fixtext: 'Configure the operating system to immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are being written to: 

# grep log_file /etc/audit/auditd.conf

Determine the size of the partition that audit records are written to (with the example being /var/log/audit/):

# df -h /var/log/audit/

Set the value of the “space_left” keyword in /etc/audit/auditd.conf to 75 percent of the partition size.'
  tag checktext: 'Verify the operating system immediately notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are being written to with the following command:

# grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the example being /var/log/audit/):

# df -h /var/log/audit/
0.9G /var/log/audit

If the audit records are not being written to a partition specifically created for audit records (in this example /var/log/audit is a separate partition), determine the amount of space other files in the partition are currently occupying with the following command:

# du -sh <partition>
1.8G /var

Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached:

# grep -i space_left /etc/audit/auditd.conf
space_left = 225 

If the value of the “space_left” keyword is not set to 75 percent of the total partition size, this is a finding.'

# START_DESCRIBE RHEL-07-030350
  describe file('/etc/audit/auditd.conf') do
    its('content') { should match /^log_file\s+=\s+.+$/ }
  end

  log_file_name = command('grep "^log_file" /etc/audit/auditd.conf | awk "{print $3}"').stdout.strip()
  log_partition_name = command("df #{log_file_name} | awk '/^\\/dev/ {print $1}'").stdout.strip()
  log_partition_size = command("df #{log_file_name} | awk '/^\\/dev/ {print $2}'").stdout.strip().to_f / 1000
  space_left = (log_partition_size - 0.75 * log_partition_size).round

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match /^space_left\s+=\s+#{space_left}$/ }
  end
# STOP_DESCRIBE RHEL-07-030350

end

