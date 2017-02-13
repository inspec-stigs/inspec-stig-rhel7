# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040700 - The SSH daemon must not allow compression or must only allow compression after successful authentication.'
control 'RHEL-07-040700' do
  impact 0.5
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  tag 'stig', 'RHEL-07-040700'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040700_chk'
  tag fixid: 'F-RHEL-07-040700_fix'
  tag version: 'RHEL-07-040700'
  tag ruleid: 'RHEL-07-040700_rule'
  tag fixtext: 'Uncomment the “Compression” keyword in /etc/ssh/sshd_config (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) on the system and set the value to "delayed" or "no":

Compression no'
  tag checktext: 'Verify the SSH daemon performs compression after a user successfully authenticates.

Check that the SSH daemon performs compression after a user successfully authenticates with the following command:

# grep -i compression /etc/ssh/sshd_config
Compression delayed

If the “Compression” keyword is set to “yes”, is missing, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040700
  describe sshd_config do
    its('Compression') { should match /^(delayed|no)$/ }
  end
# STOP_DESCRIBE RHEL-07-040700

end

