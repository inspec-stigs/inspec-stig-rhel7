# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020680 - All files and directories contained in local interactive user home directories must be owned by the owner of the home directory.'
control 'RHEL-07-020680' do
  impact 0.5
  title 'All files and directories contained in local interactive user home directories must be owned by the owner of the home directory.'
  desc 'If local interactive users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.'
  tag 'stig', 'RHEL-07-020680'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020680_chk'
  tag fixid: 'F-RHEL-07-020680_fix'
  tag version: 'RHEL-07-020680'
  tag ruleid: 'RHEL-07-020680_rule'
  tag fixtext: 'Change the owner of a local interactive user’s files and rectories to that owner. To change the owner of a local interactive user’s files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of “/home/smithj”.

# chown smithj /home/smithj/<file or directory>'
  tag checktext: 'Verify all files and directories in a local interactive user’s home directory are owned by the user.

Check the owner of all files and directories in a local interactive user’s home directory with the following command:

# ls -lLR /<home directory path>/<users home directory>/
/home/smithj
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj smithj 231 Mar  5 17:06 file3

If any files are found with an owner different than the home directory user, this is a finding.'

# START_DESCRIBE RHEL-07-020680
  find_cmd = "find %{file} 2> /dev/null"
  interactive_users = command('for i in $(ls -1 /home* && grep -v home /etc/passwd | cut -d: -f1); do getent passwd $i | awk -F\':\' \'!/nologin|false/ {if ($7 !~ $1) print $1":"$6}\'; done | sort -u').stdout.split("\n")
  interactive_users.map! { |interactive_user| {
    "username" => interactive_user.split(":")[0],
    "home_files" => command(find_cmd % {file: interactive_user.split(":")[1]}).stdout.split("\n")
    }
  }

  interactive_users.each do |interactive_user|
    interactive_user['home_files'].each do |home_file|
      describe file(home_file) do
        it { should be_owned_by interactive_user['username'] }
      end
    end
  end
# STOP_DESCRIBE RHEL-07-020680

end

