# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020670 - All local interactive user home directories must be group-owned by the home directory owners primary group.'
control 'RHEL-07-020670' do
  impact 0.5
  title 'All local interactive user home directories must be group-owned by the home directory owners primary group.'
  desc 'If the Group Identifier (GID) of a local interactive user’s home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user’s files, and users that share the same group may not be able to access files that they legitimately should.'
  tag 'stig', 'RHEL-07-020670'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020670_chk'
  tag fixid: 'F-RHEL-07-020670_fix'
  tag version: 'RHEL-07-020670'
  tag ruleid: 'RHEL-07-020670_rule'
  tag fixtext: 'Change the group owner of a local interactive user’s home directory to the group found in “/etc/passwd”. To change the group owner of a local interactive user’s home directory, use the following command:

Note: The example will be for the user “smithj”, who has a home directory of “/home/smithj”, and has a primary group of users.

# chgrp users /home/smithj'
  tag checktext: 'Verify the assigned home directory of all local interactive users is group-owned by that user’s primary GID.

Check the home directory assignment for all non-privileged users on the system with the following command:

# cut -d: -f 1,3,4 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj 250

# grep 250 /etc/group
users:x:250:smithj,jonesj,jacksons

Note: This may miss local interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the group owner of all local interactive users’ home directories with the following command:

# ls -al <users home directory>
drwxr-x---  1 smithj users        860 Nov 28 06:43 smithj

If the user home directory referenced in “/etc/passwd” is not group-owned by that user’s primary GID, this is a finding.'

# START_DESCRIBE RHEL-07-020670
  group_cmd = "id -gn %{username}"
  interactive_users = command('for i in $(ls -1 /home* && grep -v home /etc/passwd | cut -d: -f1); do getent passwd $i | awk -F\':\' \'!/nologin|false/ {if ($7 !~ $1) print $1":"$6}\'; done | sort -u').stdout.split("\n")
  interactive_users.map! { |interactive_user| {
    "username" => interactive_user.split(":")[0],
    "group" => command(group_cmd % {username: interactive_user.split(":")[0]}).stdout.strip(),
    "home" => interactive_user.split(":")[1]
    }
  }

  interactive_users.each do |interactive_user|
    describe file(interactive_user['home']) do
      it { should be_grouped_into interactive_user['group'] }
    end
  end
# STOP_DESCRIBE RHEL-07-020670

end

