# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021160 - Cron logging must be implemented.'
control 'RHEL-07-021160' do
  impact 0.5
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  tag 'stig', 'RHEL-07-021160'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021160_chk'
  tag fixid: 'F-RHEL-07-021160_fix'
  tag version: 'RHEL-07-021160'
  tag ruleid: 'RHEL-07-021160_rule'
  tag fixtext: 'Configure rsyslog to log all cron messages by adding or updating the following line to /etc/rsyslog.conf:

cron.* /var/log/cron.log

Note: The line must be added before the following entry if it exists in /etc/rsyslog.conf:
*.* ~ # discards everything'
  tag checktext: 'Verify that rsyslog is configured to log cron events.

Check the configuration of /etc/rsyslog.conf for the cron facility with the following command:

Note: If another logging package is used, substitute the utility configuration file for /etc/rsyslog.conf. 

# grep cron /etc/rsyslog.conf
cron.* /var/log/cron.log

If the command does not return a response, check for cron logging all facilities by inspecting the /etc/rsyslog.conf file:

# more /etc/rsyslog.conf

Look for the following entry:

*.* /var/log/messages

If rsyslog is not logging messages for the cron facility or all facilities, this is a finding.  

If the entry is in the “/etc/rsyslog.conf” file but is after the entry: *.*\', this is a finding.'

# START_DESCRIBE RHEL-07-021160
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-021160

end

