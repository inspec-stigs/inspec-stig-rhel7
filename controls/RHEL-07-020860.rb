# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020860 - All local initialization files must have mode 0740 or less permissive.'
control 'RHEL-07-020860' do
  impact 0.5
  title 'All local initialization files must have mode 0740 or less permissive.'
  desc 'Local initialization files are used to configure the user\'s shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.'
  tag 'stig', 'RHEL-07-020860'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020860_chk'
  tag fixid: 'F-RHEL-07-020860_fix'
  tag version: 'RHEL-07-020860'
  tag ruleid: 'RHEL-07-020860_rule'
  tag fixtext: 'Set the mode of the local initialization files to “0740” with the following command:

Note: The example will be for the smithj user, who has a home directory of “/home/smithj”.

# chmod 0740 /home/smithj/.*'
  tag checktext: 'Verify that all local initialization files have a mode of “0740” or less permissive.

Check the mode on all local initialization files with the following command:

Note: The example will be for the smithj user, who has a home directory of “/home/smithj”.

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something

If any local initialization files have a mode more permissive than “0740”, this is a finding.'

# START_DESCRIBE RHEL-07-020860
  interactive_users = command('for i in $(ls -1 /home* && grep -v home /etc/passwd | cut -d: -f1); do getent passwd $i | awk -F\':\' \'!/nologin|false/ {if ($7 !~ $1) print $1":"$6}\'; done | sort -u').stdout.split("\n")
  interactive_users.map! { |interactive_user| {
    "username" => interactive_user.split(":")[0],
    "home" => interactive_user.split(":")[1]
    }
  }

  interactive_users.each do |interactive_user|
    describe command("find #{interactive_user['home']} -perm /g=w,g=x,o=w,o=r,o=x -name '.*' 2> /dev/null") do
      its('stdout') { should eq '' }
    end
  end
# STOP_DESCRIBE RHEL-07-020860

end

