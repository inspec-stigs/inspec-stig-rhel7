# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010074 - The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated.'
control 'RHEL-07-010074' do
  impact 0.5
  title 'The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user\'s session has idled and take action to initiate the session lock.  The session lock is implemented at the point where session activity can be determined and/or controlled.'
  tag 'stig', 'RHEL-07-010074'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010074_chk'
  tag fixid: 'F-RHEL-07-010074_fix'
  tag version: 'RHEL-07-010074'
  tag ruleid: 'RHEL-07-010074_rule'
  tag fixtext: 'Configure the operating system to initiate a session lock for graphical user interfaces when a screensaver is activated.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

# touch /etc/dconf/db/local.d/00-screensaver

Add the setting to enable session locking when a screensaver is activated:

[org/gnome/desktop/screensaver]
lock-delay=uint32 5

After the setting has been set, run dconf update.'
  tag checktext: 'Verify the operating system initiates a session lock a for graphical user interfaces when the screensaver is activated. The screen program must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

If GNOME is installed, check to see a session lock occurs when the screensaver is activated with the following command:

# grep -i lock-delay /etc/dconf/db/local.d/*
lock-delay=uint32 5

If the “lock-delay” setting is missing, or is not set, this is a finding.'

# START_DESCRIBE RHEL-07-010074
  if package('gnome-desktop3').installed?
    describe command('grep -i lock-delay /etc/dconf/db/local.d/*') do
      its('stdout') { should match /uint32/ }
    end
  end
# STOP_DESCRIBE RHEL-07-010074

end

