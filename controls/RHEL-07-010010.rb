# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010010 - The file permissions, ownership, and group membership of system files and commands must match the vendor values.'
control 'RHEL-07-010010' do
  impact 1.0
  title 'The file permissions, ownership, and group membership of system files and commands must match the vendor values.'
  desc 'Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default.  Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-00108'
  tag 'stig', 'RHEL-07-010010'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010010_chk'
  tag fixid: 'F-RHEL-07-010010_fix'
  tag version: 'RHEL-07-010010'
  tag ruleid: 'RHEL-07-010010_rule'
  tag fixtext: 'Run the following command to determine which package owns the file:

# rpm -qf <filename>

Reset the permissions of files within a package with the following command:

#rpm --setperms <packagename>

Reset the user and group ownership of files within a package with the following command:

#rpm --setugids <packagename>'
  tag checktext: 'Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.
Check the file permissions, ownership, and group membership of system files and commands with the following command:

# rpm -Va | grep \'^.M\'

If there is any output from the command, this is a finding.'

# START_DESCRIBE RHEL-07-010010
  if os[:family] == 'redhat'
    describe command("rpm -Va  | grep '^.M'") do
      its('stdout') { should eq '' }
    end
  end
# STOP_DESCRIBE RHEL-07-010010

end

