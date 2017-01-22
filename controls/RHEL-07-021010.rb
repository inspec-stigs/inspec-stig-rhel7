# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021010 - Files systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed.'
control 'RHEL-07-021010' do
  impact 0.5
  title 'Files systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  tag 'stig', 'RHEL-07-021010'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021010_chk'
  tag fixid: 'F-RHEL-07-021010_fix'
  tag version: 'RHEL-07-021010'
  tag ruleid: 'RHEL-07-021010_rule'
  tag fixtext: 'Configure the “/etc/fstab” to use the “nosuid” option on file systems that contain user home directories.'
  tag checktext: 'Verify file systems that contain user home directories are mounted with the “nosetuid” option.

Find the file system(s) that contain the user home directories with the following command:

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under “/”) this is not a finding as the “nosetuid” option cannot be used on the “/” system.

# cut -d: -f 1,7 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj
thomasr /home/thomasr

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home   ext4   rw,relatime,discard,data=ordered,nosuid                                                                         0 2

If a file system found in “/etc/fstab” refers to the user home directory file system and it does not have the “nosetuid” option set, this is a finding.'

# START_DESCRIBE RHEL-07-021010
  fstab_lines = file('/etc/fstab').content.split("\n")
  fstab_lines.each do |fstab_line|
    if fstab_line.include? 'home' and fstab_line !~ /^#/
      describe command("echo '#{fstab_line}'") do
        its('stdout') { should match /nosetuid/ }
      end
    end
  end
# STOP_DESCRIBE RHEL-07-021010

end

