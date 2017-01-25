# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021011 - Files systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed.'
control 'RHEL-07-021011' do
  impact 0.5
  title 'Files systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  tag 'stig', 'RHEL-07-021011'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021011_chk'
  tag fixid: 'F-RHEL-07-021011_fix'
  tag version: 'RHEL-07-021011'
  tag ruleid: 'RHEL-07-021011_rule'
  tag fixtext: 'Configure the “/etc/fstab” to use the “nosuid” option on file systems that are associated with removable media.'
  tag checktext: 'Verify file systems that are used for removable media are mounted with the “nosetuid” option.

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222     /mnt/usbflash      vfat   noauto,owner,ro,nosuid                        0 0

If a file system found in “/etc/fstab” refers to removable media and it does not have the “nosetuid” option set, this is a finding.'

# START_DESCRIBE RHEL-07-021011
  fstab_lines = file('/etc/fstab').content.split("\n")
  fstab_lines.each do |fstab_line|
    if fstab_line =~ /mnt|media/ and fstab_line !~ /^#/
      describe command("echo '#{fstab_line}'") do
        its('stdout') { should match /nosetuid/ }
      end
    end
  end
# STOP_DESCRIBE RHEL-07-021011

end

