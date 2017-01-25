# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020650 - All local interactive user home directories must have mode 0750 or less permissive.'
control 'RHEL-07-020650' do
  impact 0.5
  title 'All local interactive user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.'
  tag 'stig', 'RHEL-07-020650'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020650_chk'
  tag fixid: 'F-RHEL-07-020650_fix'
  tag version: 'RHEL-07-020650'
  tag ruleid: 'RHEL-07-020650_rule'
  tag fixtext: 'Change the mode of interactive user’s home directories to “0750”. To change the mode of a local interactive user’s home directory, use the following command:

Note: The example will be for the user “smithj”.

# chmod 0750 /home/smithj'
  tag checktext: 'Verify the assigned home directory of all local interactive users has a mode of “0750” or less permissive.

Check the home directory assignment for all non-privileged users on the system with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the mode on all local interactive users’ home directories with the following command:

# ls -al <users home directory>
drwxr-x---  1 smithj users        860 Nov 28 06:43 smithj

If home directories referenced in “/etc/passwd” do not have a mode of “0750” or less permissive, this is a finding.'

# START_DESCRIBE RHEL-07-020650
  interactive_users = command('for i in $(ls -1 /home* && grep -v home /etc/passwd | cut -d: -f1); do getent passwd $i | awk -F\':\' \'!/nologin|false/ {if ($7 !~ $1) print $1":"$6}\'; done | sort -u').stdout.split("\n")
  interactive_users.map! { |interactive_user| {
    "username" => interactive_user.split(":")[0],
    "home" => interactive_user.split(":")[1]
    }
  }

  interactive_users.each do |interactive_user|
    describe command("find #{interactive_user['home']} -maxdepth 0 -perm /g=w,o=w,o=r,o=x 2> /dev/null") do
      its('stdout') { should eq '' }
    end
  end
# STOP_DESCRIBE RHEL-07-020650

end

