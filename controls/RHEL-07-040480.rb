# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040480 - The system must be configured to prevent unrestricted mail relaying.'
control 'RHEL-07-040480' do
  impact 0.5
  title 'The system must be configured to prevent unrestricted mail relaying.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.'
  tag 'stig', 'RHEL-07-040480'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040480_chk'
  tag fixid: 'F-RHEL-07-040480_fix'
  tag version: 'RHEL-07-040480'
  tag ruleid: 'RHEL-07-040480_rule'
  tag fixtext: 'If “postfix” is installed, modify the “/etc/postfix/main.cf” file to restrict client connections to the local network with the following configuration line:

smtpd_client_restrictions = permit_mynetworks, reject'
  tag checktext: 'Verify the system is configured to prevent unrestricted mail relaying.

Determine if "postfix" or "sendmail" are installed with the following commands:

# yum list installed | grep postfix
postfix-2.6.6-6.el7.x86_64.rpm 
# yum list installed | grep sendmail

If neither are installed, this is Not Applicable.

If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:

# grep smtpd_client_restrictions /etc/postfix/main.cf
smtpd_client_restrictions = permit_mynetworks, reject

If the “smtpd_client_restrictions” parameter contains any entries other than "permit_mynetworks" and "reject", this is a finding.'

# START_DESCRIBE RHEL-07-040480
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040480

end

