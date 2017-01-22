# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010490 - Unnecessary default system accounts must be removed.'
control 'RHEL-07-010490' do
  impact 0.1
  title 'Unnecessary default system accounts must be removed.'
  desc 'Default system accounts created at install time but never used by the system may inadvertently be configured for interactive logon. Vendor accounts and software may contain accounts that provide unauthorized access to the system. All accounts that are not used to support the system and application operation must be removed from the system.'
  tag 'stig', 'RHEL-07-010490'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-010490_chk'
  tag fixid: 'F-RHEL-07-010490_fix'
  tag version: 'RHEL-07-010490'
  tag ruleid: 'RHEL-07-010490_rule'
  tag fixtext: 'Remove unnecessary default accounts from the system by using the account management tool or manually editing the “/etc/password” and “/etc/shadow” files.'
  tag checktext: 'Verify unnecessary default system accounts have been removed.

Check the accounts that are on the system with the following command:

# more /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync

If unnecessary default accounts such as games or ftp exist in the “/etc/passwd” file, this is a finding.'

# START_DESCRIBE RHEL-07-010490
  describe file('/etc/passwd') do
    its('content') { should_not match /^(games|ftp)/ }
  end
# STOP_DESCRIBE RHEL-07-010490

end

