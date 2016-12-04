# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030340 - The audit system must take appropriate action when the audit storage volume is full.'
control 'RHEL-07-030340' do
  impact 0.5
  title 'The audit system must take appropriate action when the audit storage volume is full.'
  desc 'Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.'
  tag 'stig', 'RHEL-07-030340'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030340_chk'
  tag fixid: 'F-RHEL-07-030340_fix'
  tag version: 'RHEL-07-030340'
  tag ruleid: 'RHEL-07-030340_rule'
  tag fixtext: 'Configure the operating system to off-load audit records onto a different system or media from the system being audited.

Uncomment or edit the "disk_full_action" option in /etc/audisp/audisp-remote.conf and set it to syslog, single, or halt, such as the following line:

disk_full_action = single

Uncomment the network_failure_action option in /etc/audisp/audisp-remote.conf and set it to syslog, single, or halt.'
  tag checktext: 'Verify the action the operating system takes if the disk the audit records are written to becomes full.

To determine the action that takes place if the disk is full on the remote server, use the following command:

# grep -i disk_full_action /etc/audisp/audisp-remote.conf
disk_full_action = single

To determine the action that takes place if the network connection fails, use the following command:

# grep -i network_failure_action /etc/audisp/audisp-remote.conf
network_failure_action = stop

If the value of the “network_failure_action” option is not “syslog”, “single”, or “halt”, or the line is commented out, this is a finding.

If the value of the “disk_full_action” option is not "syslog", "single", or "halt", or the line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-030340
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030340

end

