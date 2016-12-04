# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010431 - The operating system must not allow guest logon to the system.'
control 'RHEL-07-010431' do
  impact 1.0
  title 'The operating system must not allow guest logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  tag 'stig', 'RHEL-07-010431'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010431_chk'
  tag fixid: 'F-RHEL-07-010431_fix'
  tag version: 'RHEL-07-010431'
  tag ruleid: 'RHEL-07-010431_rule'
  tag fixtext: 'Configure the operating system to not allow a guest account to log on to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the “TimedLoginEnable” parameter in the [daemon] section of the “/etc/gdm/custom.conf” file to “false”:

[daemon]
TimedLoginEnable=false'
  tag checktext: 'Verify the operating system does not allow guest logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the “AutomaticLoginEnable” in “/etc/gdm/custom.conf” file with the following command:

# grep -i timedloginenable /etc/gdm/custom.conf
TimedLoginEnable=false

If the value of “TimedLoginEnable” is not set to “false”, this is a finding.'

# START_DESCRIBE RHEL-07-010431
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-010431

end

