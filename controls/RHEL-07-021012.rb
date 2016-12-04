# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021012 - Files systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed.'
control 'RHEL-07-021012' do
  impact 0.5
  title 'Files systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  tag 'stig', 'RHEL-07-021012'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021012_chk'
  tag fixid: 'F-RHEL-07-021012_fix'
  tag version: 'RHEL-07-021012'
  tag ruleid: 'RHEL-07-021012_rule'
  tag fixtext: 'Configure the “/etc/fstab” to use the “nosuid” option on file systems that are being exported via NFS.'
  tag checktext: 'Verify file systems that are being NFS exported are mounted with the “nosetuid” option.

Find the file system(s) that contain the directories being exported with the following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d    /store           nfs           rw,nosuid                                                    0 0

If a file system found in “/etc/fstab” refers to NFS and it does not have the “nosuid” option set, this is a finding.'

# START_DESCRIBE RHEL-07-021012
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-021012

end

