# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021270 - The system must use a separate file system for /tmp (or equivalent).'
control 'RHEL-07-021270' do
  impact 0.1
  title 'The system must use a separate file system for /tmp (or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  tag 'stig', 'RHEL-07-021270'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-021270_chk'
  tag fixid: 'F-RHEL-07-021270_fix'
  tag version: 'RHEL-07-021270'
  tag ruleid: 'RHEL-07-021270_rule'
  tag fixtext: 'Migrate the /tmp path onto a separate file system.'
  tag checktext: 'Verify that a separate file system/partition has been created for /tmp.

Check that a file system/partition has been created for “/tmp” with the following command:

# grep /tmp /etc/fstab
UUID=7835718b    /tmp    ext4    nodev,nosetuid,noexec      1 2

If a separate entry for /tmp is not in use, this is a finding.'

# START_DESCRIBE RHEL-07-021270
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-021270

end

