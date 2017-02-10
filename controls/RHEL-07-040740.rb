# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040740 - The Network File System (NFS) must be configured to use AUTH_GSS.'
control 'RHEL-07-040740' do
  impact 0.5
  title 'The Network File System (NFS) must be configured to use AUTH_GSS.'
  desc 'When an NFS server is configured to use AUTH_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The AUTH_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request.'
  tag 'stig', 'RHEL-07-040740'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040740_chk'
  tag fixid: 'F-RHEL-07-040740_fix'
  tag version: 'RHEL-07-040740'
  tag ruleid: 'RHEL-07-040740_rule'
  tag fixtext: 'Update the “/etc/fstab” file so the option “sec” is defined for each file system and the “sec” option does not have the “sys” setting. 

Ensure the “sec” option is defined as “krb5:krb5i:krb5p”.'
  tag checktext: 'Verify “AUTH_GSS’ is being used to authenticate NFS mounts.

To check if the system is importing an NFS file system, look for any entries in the “/etc/fstab” file that have a file system type of “nfs” with the following command:

# cat /etc/fstab | grep nfs
192.168.21.5:/mnt/export /data1 nfs4 rw,sync ,soft,sec=sys, krb5:krb5i:krb5p

If the system is mounting file systems via NFS and has the sec option without the “krb5:krb5i:krb5p” settings, the sec option has the “sys” setting, or the “sec” option is missing, this is a finding.'

# START_DESCRIBE RHEL-07-040740
  begin
    fstab_lines = file('/etc/fstab').content.split("\n")
  rescue NoMethodError
    fstab_lines = []
  end

  fstab_lines.each do |fstab_line|
    if fstab_line.include? 'nfs' and fstab_line !~ /^#/
      describe command("echo '#{fstab_line}'") do
        its('stdout') { should match /sec=(krb5p|krb5i|krb5)/ }
      end
    end
  end
# STOP_DESCRIBE RHEL-07-040740

end

