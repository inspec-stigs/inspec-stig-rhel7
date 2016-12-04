# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010072 - The operating system must have the screen package installed.'
control 'RHEL-07-010072' do
  impact 0.5
  title 'The operating system must have the screen package installed.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user\'s session has idled and take action to initiate the session lock.  The screen package allows for a session lock to be implemented and configured.'
  tag 'stig', 'RHEL-07-010072'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010072_chk'
  tag fixid: 'F-RHEL-07-010072_fix'
  tag version: 'RHEL-07-010072'
  tag ruleid: 'RHEL-07-010072_rule'
  tag fixtext: 'Install the screen package to allow the initiation a session lock after a 15-minute period of inactivity for graphical users interfaces.

Install the screen program (if it is not on the system) with the following command:

# yum install screen

The console can now be locked with the following key combination:

ctrl+a x'
  tag checktext: 'Verify the operating system has the screen package installed.

Check to see if the screen package is installed with the following command:

# yum list installed | grep screen
screen-4.3.1-3-x86_64.rpm

If is not installed, this is a finding.'

# START_DESCRIBE RHEL-07-010072
  describe package('screen') do
    it { should be_installed }
  end
# STOP_DESCRIBE RHEL-07-010072

end

