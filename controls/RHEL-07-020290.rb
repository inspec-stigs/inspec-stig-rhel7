# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020290 - The system must not have unnecessary accounts.'
control 'RHEL-07-020290' do
  impact 0.5
  title 'The system must not have unnecessary accounts.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  tag 'stig', 'RHEL-07-020290'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020290_chk'
  tag fixid: 'F-RHEL-07-020290_fix'
  tag version: 'RHEL-07-020290'
  tag ruleid: 'RHEL-07-020290_rule'
  tag fixtext: 'Configure the system so all accounts on the system are assigned to an active system, application, or user account. Remove accounts that do not support approved system activities or that allow for a normal user to perform administrative-level actions. Document all authorized accounts on the system.'
  tag checktext: 'Verify all accounts on the system are assigned to an active system, application, or user account.

Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).

Check the system accounts on the system with the following command:

# more /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin

Accounts such as “games” and “gopher” are not authorized accounts as they do not support authorized system functions. 

If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding.'

# START_DESCRIBE RHEL-07-020290
  describe file('/etc/passwd') do
    its('content') { should_not match /^(games|gopher)/ }
  end
# STOP_DESCRIBE RHEL-07-020290

end

