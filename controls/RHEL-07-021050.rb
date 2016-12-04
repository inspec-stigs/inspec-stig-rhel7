# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021050 - All world-writable directories must be group-owned by root, sys, bin, or an application group.'
control 'RHEL-07-021050' do
  impact 0.5
  title 'All world-writable directories must be group-owned by root, sys, bin, or an application group.'
  desc 'If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.  The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  tag 'stig', 'RHEL-07-021050'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021050_chk'
  tag fixid: 'F-RHEL-07-021050_fix'
  tag version: 'RHEL-07-021050'
  tag ruleid: 'RHEL-07-021050_rule'
  tag fixtext: 'Change the group of the world-writable directories to root with the following command:

# chgrp root <directory>'
  tag checktext: 'Verify all world-writable directories are group-owned by root, sys, bin, or an application group.

Check the system for world-writable directories with the following command:

# find / -perm -002 -type d -exec ls -lLd {} \;
drwxrwxrwt. 2 root root 40 Aug 26 13:07 /dev/mqueue
drwxrwxrwt. 2 root root 220 Aug 26 13:23 /dev/shm
drwxrwxrwt. 14 root root 4096 Aug 26 13:29 /tmp

If any world-writable directories are not owned by root, sys, bin, or an application group associated with the directory, this is a finding.'

# START_DESCRIBE RHEL-07-021050
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-021050

end

