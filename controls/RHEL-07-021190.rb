# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021190 - If the cron.allow file exists it must be owned by root.'
control 'RHEL-07-021190' do
  impact 0.5
  title 'If the cron.allow file exists it must be owned by root.'
  desc 'If the owner of the "cron.allow" file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information.'
  tag 'stig', 'RHEL-07-021190'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021190_chk'
  tag fixid: 'F-RHEL-07-021190_fix'
  tag version: 'RHEL-07-021190'
  tag ruleid: 'RHEL-07-021190_rule'
  tag fixtext: 'Set the owner on the “/etc/cron.allow” file to root with the following command:

# chown root /etc/cron.allow'
  tag checktext: 'Verify that the "cron.allow" file is owned by root.

Check the owner of the "cron.allow" file with the following command:

# l s -al /etc/cron.allow
-rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow

If the “cron.allow” file exists and has an owner other than root, this is a finding.'

# START_DESCRIBE RHEL-07-021190
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-021190

end

