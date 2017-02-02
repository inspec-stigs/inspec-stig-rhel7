# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040160 - All network connections associated with a communication session must be terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements.'
control 'RHEL-07-040160' do
  impact 0.5
  title 'All network connections associated with a communication session must be terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.   Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  tag 'stig', 'RHEL-07-040160'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040160_chk'
  tag fixid: 'F-RHEL-07-040160_fix'
  tag version: 'RHEL-07-040160'
  tag ruleid: 'RHEL-07-040160_rule'
  tag fixtext: 'Configure the operating system to terminate all network connections associated with a communications session at the end of the session or after a period of inactivity.

Add the following line to /etc/profile (or modify the line to have the required value):

TMOUT=600'
  tag checktext: 'Verify the operating system terminates all network connections associated with a communications session at the end of the session or based on inactivity.

Check the value of the system inactivity timeout with the following command:

# grep -i tmout /etc/profile 
TMOUT=600

If “TMOUT” is not set to 600 or less in /etc/profile, this is a finding.'

# START_DESCRIBE RHEL-07-040160
  describe command('grep -rE "^(export\s+)?TMOUT=([0-9]|[1-8][0-9]|9[0-9]|[1-5][0-9]{2}|600$)$" /etc/profile*') do
    its('exit_status') { should eq 0 }
  end
# STOP_DESCRIBE RHEL-07-040160

end

