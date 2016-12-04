# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030330 - The operating system must off-load audit records onto a different system or media from the system being audited.'
control 'RHEL-07-030330' do
  impact 0.5
  title 'The operating system must off-load audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.  Off-loading is a common process in information systems with limited audit storage capacity.  Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224'
  tag 'stig', 'RHEL-07-030330'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030330_chk'
  tag fixid: 'F-RHEL-07-030330_fix'
  tag version: 'RHEL-07-030330'
  tag ruleid: 'RHEL-07-030330_rule'
  tag fixtext: 'Configure the operating system to off-load audit records onto a different system or media from the system being audited.

Set the remote server option in /etc/audisp/audisp-remote.conf with the IP address of the log aggregation server.'
  tag checktext: 'Verify the operating system off-loads audit records onto a different system or media from the system being audited.

To determine the remote server that the records are being sent to, use the following command:

# grep -i remote_server /etc/audisp/audisp-remote.conf
remote_server = 10.0.21.1

If a remote server is not configured, or the line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-030330
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030330

end

