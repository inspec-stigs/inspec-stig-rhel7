# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020690 - All files and directories contained in local interactive user home directories must be group-owned by a group of which the home directory owner is a member.'
control 'RHEL-07-020690' do
  impact 0.5
  title 'All files and directories contained in local interactive user home directories must be group-owned by a group of which the home directory owner is a member.'
  desc 'If a local interactive user’s files are group-owned by a group of which the user is not a member, unintended users may be able to access them.'
  tag 'stig', 'RHEL-07-020690'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020690_chk'
  tag fixid: 'F-RHEL-07-020690_fix'
  tag version: 'RHEL-07-020690'
  tag ruleid: 'RHEL-07-020690_rule'
  tag fixtext: 'Change the group of a local interactive user’s files and directories to a group that the interactive user is a member of. To change the group owner of a local interactive user’s files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of “/home/smithj” and is a member of the users group.

# chgrp users /home/smithj/<file>'
  tag checktext: 'Verify all files and directories in a local interactive user home directory are group-owned by a group the user is a member of.

Check the group owner of all files and directories in a local interactive user’s home directory with the following command:

Note: The example will be for the user “smithj”, who has a home directory of “/home/smithj/home/smithj”.

# ls -lLR /<home directory>/<users home directory>/
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with an owner different than the group home directory user, check to see if the user is a member of that group with the following command:

# grep smithj /etc/group
sa:x:100:juan,shelley,bob,smithj 
smithj:x:521:smithj

If the user is not a member of a group that group owns file(s) in a local interactive user’s home directory, this is a finding.'

# START_DESCRIBE RHEL-07-020690
  find_cmd = "find %{file} 2> /dev/null"
  group_cmd = "id -Gn %{username}"
  interactive_users = command('for i in $(ls -1 /home* && grep -v home /etc/passwd | cut -d: -f1); do getent passwd $i | awk -F\':\' \'!/nologin|false/ {if ($7 !~ $1) print $1":"$6}\'; done | sort -u').stdout.split("\n")
  interactive_users.map! { |interactive_user| {
    "username" => interactive_user.split(":")[0],
    "home_files" => command(find_cmd % {file: interactive_user.split(":")[1]}).stdout.split("\n"),
    "groups" => command(group_cmd % {username: interactive_user.split(":")[0]}).stdout.split(" ")
    }
  }

  interactive_users.each do |interactive_user|
    interactive_user['home_files'].each do |home_file|
      describe.one do
        interactive_user['groups'].each do |group|
          describe file(home_file) do
            it { should be_grouped_into group }
          end
        end
      end
    end
  end
# STOP_DESCRIBE RHEL-07-020690

end

