# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020850 - Local initialization files for local interactive users must be group-owned by the users primary group or root.'
control 'RHEL-07-020850' do
  impact 0.5
  title 'Local initialization files for local interactive users must be group-owned by the users primary group or root.'
  desc 'Local initialization files for interactive users are used to configure the user\'s shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.'
  tag 'stig', 'RHEL-07-020850'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020850_chk'
  tag fixid: 'F-RHEL-07-020850_fix'
  tag version: 'RHEL-07-020850'
  tag ruleid: 'RHEL-07-020850_rule'
  tag fixtext: 'Change the group owner of a local interactive user’s files to the group found in “/etc/passwd” for the user. To change the group owner of a local interactive user home directory, use the following command:

Note: The example will be for the user smithj, who has a home directory of “/home/smithj”, and has a primary group of users.

# chgrp users /home/smithj/<file>'
  tag checktext: 'Verify the local initialization files of all local interactive users are group-owned by that user’s primary Group Identifier (GID).

Check the home directory assignment for all non-privileged users on the system with the following command:

Note: The example will be for the smithj user, who has a home directory of “/home/smithj” and a primary group of users.

# cut -d: -f 1,3,4 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj 250

# grep 250 /etc/group
users:x:250:smithj,jonesj,jacksons 

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the group owner of all local interactive users’ initialization files with the following command:

# ls -al /home/smithj/.*
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something

If all local interactive users’ initialization files are not group-owned by that user’s primary GID, this is a finding.'

# START_DESCRIBE RHEL-07-020850
  find_cmd = "find %{file} -mindepth 1 -type f -prune -name '.*' ! -name '*.swp' 2> /dev/null"
  group_cmd = "id -gn %{username}"
  interactive_users = command('for i in $(ls -1 /home* && grep -v home /etc/passwd | cut -d: -f1); do getent passwd $i | awk -F\':\' \'!/nologin|false/ {if ($7 !~ $1) print $1":"$6}\'; done | sort -u').stdout.split("\n")
  interactive_users.map! { |interactive_user| {
    "username" => interactive_user.split(":")[0],
    "group" => command(group_cmd % {username: interactive_user.split(":")[0]}).stdout.strip(),
    "init_files" => command(find_cmd % {file: interactive_user.split(":")[1]}).stdout.split("\n")
    }
  }

  interactive_users.each do |interactive_user|
    interactive_user['init_files'].each do |init_file|
      describe file(init_file) do
        it { should be_grouped_into interactive_user['group'] }
      end
    end
  end
# STOP_DESCRIBE RHEL-07-020850

end

