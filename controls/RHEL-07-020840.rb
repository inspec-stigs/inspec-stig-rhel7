# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020840 - All local initialization files for interactive users must be owned by the home directory user or root.'
control 'RHEL-07-020840' do
  impact 0.5
  title 'All local initialization files for interactive users must be owned by the home directory user or root.'
  desc 'Local initialization files are used to configure the user\'s shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.'
  tag 'stig', 'RHEL-07-020840'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020840_chk'
  tag fixid: 'F-RHEL-07-020840_fix'
  tag version: 'RHEL-07-020840'
  tag ruleid: 'RHEL-07-020840_rule'
  tag fixtext: 'Set the owner of the local initialization files for interactive users to either the directory owner or root with the following command:

Note: The example will be for the smithj user, who has a home directory of “/home/smithj”.

# chown smithj /home/smithj/.*'
  tag checktext: 'Verify all local initialization files for interactive users are owned by the home directory user or root.

Check the owner on all local initialization files with the following command:

Note: The example will be for the “smithj” user, who has a home directory of “/home/smithj”.

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .bash_profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .profile

If any file that sets a local interactive user’s environment variables to override the system is not owned by the home directory owner or root, this is a finding.'

# START_DESCRIBE RHEL-07-020840
  find_cmd = "find %{file} -mindepth 1 -type f -prune -name '.*' ! -name '*.swp' 2> /dev/null"
  interactive_users = command('for i in $(ls -1 /home* && grep -v home /etc/passwd | cut -d: -f1); do getent passwd $i | awk -F\':\' \'!/nologin|false/ {if ($7 !~ $1) print $1":"$6}\'; done | sort -u').stdout.split("\n")
  interactive_users.map! { |interactive_user| {
    "username" => interactive_user.split(":")[0],
    "init_files" => command(find_cmd % {file: interactive_user.split(":")[1]}).stdout.split("\n")
    }
  }

  interactive_users.each do |interactive_user|
    interactive_user['init_files'].each do |init_file|
      describe.one do
        describe file(init_file) do
          it { should be_owned_by interactive_user['username'] }
        end

        describe file(init_file) do
          it { should be_owned_by 'root' }
        end
      end
    end
  end
# STOP_DESCRIBE RHEL-07-020840

end

