# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040020 - The system must log informational authentication data.'
control 'RHEL-07-040020' do
  impact 0.5
  title 'The system must log informational authentication data.'
  desc 'Access services, such as those providing remote access to network devices and information systems, that lack automated monitoring capabilities increase risk and make remote user access management difficult at best.  Automated monitoring of access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  tag 'stig', 'RHEL-07-040020'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040020_chk'
  tag fixid: 'F-RHEL-07-040020_fix'
  tag version: 'RHEL-07-040020'
  tag ruleid: 'RHEL-07-040020_rule'
  tag fixtext: 'Configure the operating system to log informational authentication data.

Add the following rules to the /etc/rsyslog.conf file:

auth.*,authpriv.* /var/log/auth.log
daemon.notice /var/log/messages'
  tag checktext: 'Verify the operating system logs informational authentication data.

Check to see if rsyslog is logging authentication information with the following commands:

# grep auth* /etc/rsyslog.conf
auth,authpriv.debug /var/log/auth.log

# grep daemon.* /etc/rsyslog.conf
daemon.notice /var/log/messages

If the auth, authpriv, and daemon facilities are not being logged, or they are being logged at a priority of notice or higher, this is a finding.'

# START_DESCRIBE RHEL-07-040020
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040020

end

