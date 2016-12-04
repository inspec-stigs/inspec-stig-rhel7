# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010060 - The operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.'
control 'RHEL-07-010060' do
  impact 0.5
  title 'The operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.  The session lock is implemented at the point where session activity can be determined.  Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.  Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011'
  tag 'stig', 'RHEL-07-010060'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010060_chk'
  tag fixid: 'F-RHEL-07-010060_fix'
  tag version: 'RHEL-07-010060'
  tag ruleid: 'RHEL-07-010060_rule'
  tag fixtext: 'Configure the operating system to enable a user\'s session lock until that user re-establishes access using established identification and authentication procedures.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

# touch /etc/dconf/db/local.d/00-screensaver

Add the setting to enable screensaver locking to the file:

[org/gnome/desktop/screensaver]
lock-enabled=true

After the setting has been set, run dconf update.'
  tag checktext: 'Verify the operating system enables a user\'s session lock until that user re-establishes access using established identification and authentication procedures. The screen program must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Check to see if the screen lock is enabled with the following command:

# grep -i lock-enabled /etc/dconf/db/local.d/00-screensaver
lock-enabled=true

If the "lock-enabled" setting is missing or is not set to true, this is a finding.'

# START_DESCRIBE RHEL-07-010060
  if package('gnome-desktop3').installed?
    describe command('grep -i lock-enabled /etc/dconf/db/local.d/*') do
      its('stdout') { should match /lock-enabled=true/ }
    end
  end
# STOP_DESCRIBE RHEL-07-010060

end

