# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
only_if do
  package('gnome-desktop3').installed?
end

title 'RHEL-07-010071 - The operating system must initiate a session lock after a 15-minute period of inactivity for all connection types.'
control 'RHEL-07-010071' do
  impact 0.5
  title 'The operating system must initiate a session lock after a 15-minute period of inactivity for all connection types.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user\'s session has idled and take action to initiate the session lock.  The session lock is implemented at the point where session activity can be determined and/or controlled.'
  tag 'stig', 'RHEL-07-010071'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010071_chk'
  tag fixid: 'F-RHEL-07-010071_fix'
  tag version: 'RHEL-07-010071'
  tag ruleid: 'RHEL-07-010071_rule'
  tag fixtext: 'Configure the operating system to initiate a session lock after a 15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

# touch /etc/dconf/db/local.d/locks/session

Add the settings to enable screensaver/session locking after 15 minutes of inactivity:

/org/gnome/desktop/screensaver/idle-delay
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/session/idle-delay'
  tag checktext: 'Verify the operating system prevents the user from overriding session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.

If it is installed, GNOME must be configured to prevent users from overriding the system-wide session lock settings. Check for the session lock settings with the following commands:

# grep -i idle-delay /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/idle-delay
/org/gnome/desktop/session/idle-delay

If the command does not return a result for the screensaver and session keywords, this is a finding.

# grep -i lock-delay /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/lock-delay

If the command does not return a result, this is a finding.'

# START_DESCRIBE RHEL-07-010071
  describe command('grep -i lock-delay /etc/dconf/db/local.d/locks/*') do
    its('stdout') { should_not be "" }
  end
end
# STOP_DESCRIBE RHEL-07-010071
