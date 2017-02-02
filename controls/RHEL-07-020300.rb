# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020300 - All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.'
control 'RHEL-07-020300' do
  impact 0.1
  title 'All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.'
  tag 'stig', 'RHEL-07-020300'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-020300_chk'
  tag fixid: 'F-RHEL-07-020300_fix'
  tag version: 'RHEL-07-020300'
  tag ruleid: 'RHEL-07-020300_rule'
  tag fixtext: 'Configure the system to define all GIDs found in the “/etc/passwd” file by modifying the “/etc/group” file to add any non-existent group referenced in the “/etc/passwd” file, or change the GIDs referenced in the “/etc/passwd” file to a group that exists in “/etc/group”.'
  tag checktext: 'Verify all GIDs referenced in the “/etc/passwd” file are defined in the “/etc/group” file.

Check that all referenced GIDs exist with the following command:

# pwck -r

If GIDs referenced in "/etc/passwd" file are returned as not defined in "/etc/group" file, this is a finding.'

# START_DESCRIBE RHEL-07-020300
  describe command('pwck -r') do
    its('stdout') { should_not match /^user\s+'.*':\s+no\s+group\s+.*$/ }
  end
# STOP_DESCRIBE RHEL-07-020300

end

