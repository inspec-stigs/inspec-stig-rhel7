# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030780 - The rsyslog daemon must not accept log messages from other servers unless the server is being used for log aggregation.'
control 'RHEL-07-030780' do
  impact 0.5
  title 'The rsyslog daemon must not accept log messages from other servers unless the server is being used for log aggregation.'
  desc 'Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system\'s logs, or could fill the system\'s storage leading to a Denial of Service. If the system is intended to be a log aggregation server its use must be documented with the ISSO.'
  tag 'stig', 'RHEL-07-030780'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030780_chk'
  tag fixid: 'F-RHEL-07-030780_fix'
  tag version: 'RHEL-07-030780'
  tag ruleid: 'RHEL-07-030780_rule'
  tag fixtext: 'Modify the “/etc/rsyslog.conf” file to remove the “ModLoad imtcp” configuration line, or document the system as being used for log aggregation.'
  tag checktext: 'Verify that the system is not accepting "rsyslog" messages from other systems unless it is documented as a log aggregation server.

Check the configuration of rsyslog with the following command:

# grep imtcp /etc/rsyslog.conf
ModLoad imtcp

If the "imtcp" module is being loaded in the "/etc/rsyslog.conf" file ask to see the documentation for the system being used for log aggregation.

If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding.'

# START_DESCRIBE RHEL-07-030780
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030780

end

