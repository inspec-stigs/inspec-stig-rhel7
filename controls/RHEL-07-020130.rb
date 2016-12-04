# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020130 - A file integrity tool must verify the baseline operating system configuration at least weekly.'
control 'RHEL-07-020130' do
  impact 0.5
  title 'A file integrity tool must verify the baseline operating system configuration at least weekly.'
  desc 'Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.  Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system\'s Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.'
  tag 'stig', 'RHEL-07-020130'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020130_chk'
  tag fixid: 'F-RHEL-07-020130_fix'
  tag version: 'RHEL-07-020130'
  tag ruleid: 'RHEL-07-020130_rule'
  tag fixtext: 'Configure the file integrity tool to automatically run on the system at least weekly. The following example output is generic. It will set cron to run AIDE daily, but other file integrity tools may be used:

# cat /etc/cron.daily/aide 
0 0 * * * /usr/sbin/aide --check | /bin/mail -s "aide integrity check run for <system name>" root@sysname.mil'
  tag checktext: 'Verify the operating system routinely checks that baseline configuration changes are not performed in an authorized manner.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.

Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. The command used in the example will use a daily occurrence.

Check the /etc/cron.daily subdirectory for a crontab file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

# ls -al /etc/cron.* | grep aide
-rwxr-xr-x  1 root root        29 Nov  22  2015 aide

If the file integrity application is not executed on the system with the required frequency, this is a finding.'

# START_DESCRIBE RHEL-07-020130
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020130

end

