# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030770 - The system must send rsyslog output to a log aggregation server.'
control 'RHEL-07-030770' do
  impact 0.5
  title 'The system must send rsyslog output to a log aggregation server.'
  desc 'Sending rsyslog output to another system ensures that the logs cannot be removed or modified in the event that the system is compromised or has a hardware failure.'
  tag 'stig', 'RHEL-07-030770'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030770_chk'
  tag fixid: 'F-RHEL-07-030770_fix'
  tag version: 'RHEL-07-030770'
  tag ruleid: 'RHEL-07-030770_rule'
  tag fixtext: 'Modify the “/etc/rsyslog.conf” file to contain a configuration line to send all “rsyslog” output to a log aggregation system:

*.* @@<log aggregation system name>'
  tag checktext: 'Verify “rsyslog” is configured to send all messages to a log aggregation server.

Check the configuration of “rsyslog” with the following command:

# grep @ /etc/rsyslog.conf
*.* @@logagg.site.mil

If there are no lines in the “/etc/rsyslog.conf” file that contain the “@” or “@@” symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all “rsyslog” output, this is a finding.'

# START_DESCRIBE RHEL-07-030770
  describe file('/etc/rsyslog.conf') do
    it { should match /^\*\.\*\s+@{1,2}.+$/ }
  end
# STOP_DESCRIBE RHEL-07-030770

end

