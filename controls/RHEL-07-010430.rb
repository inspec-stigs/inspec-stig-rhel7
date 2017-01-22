# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010430 - The operating system must not allow an unattended or automatic logon to the system via a graphical user interface.'
control 'RHEL-07-010430' do
  impact 1.0
  title 'The operating system must not allow an unattended or automatic logon to the system via a graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  tag 'stig', 'RHEL-07-010430'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010430_chk'
  tag fixid: 'F-RHEL-07-010430_fix'
  tag version: 'RHEL-07-010430'
  tag ruleid: 'RHEL-07-010430_rule'
  tag fixtext: 'Configure the operating system to not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the “AutomaticLoginEnable” parameter in the [daemon] section of the “/etc/gdm/custom.conf” file to “false”:

[daemon]
AutomaticLoginEnable=false'
  tag checktext: 'Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the “AutomaticLoginEnable” in “/etc/gdm/custom.conf” file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of “AutomaticLoginEnable” is not set to “false”, this is a finding.'

# START_DESCRIBE RHEL-07-010430
  gdm_custom_file_exists = file('/etc/gdm/custom.conf').file?
  if gdm_custom_file_exists
    describe file('/etc/gdm/custom.conf') do
      its('content') { should match /^AutomaticLoginEnable=false$/ }
    end
  end
# STOP_DESCRIBE RHEL-07-010430

end

