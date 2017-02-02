# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040334 - The SSH daemon must not allow authentication using rhosts authentication.'
control 'RHEL-07-040334' do
  impact 0.5
  title 'The SSH daemon must not allow authentication using rhosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  tag 'stig', 'RHEL-07-040334'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040334_chk'
  tag fixid: 'F-RHEL-07-040334_fix'
  tag version: 'RHEL-07-040334'
  tag ruleid: 'RHEL-07-040334_rule'
  tag fixtext: 'Configure the SSH daemon to not allow authentication using known hosts authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to “yes”:

IgnoreRhosts yes'
  tag checktext: 'Verify the SSH daemon does not allow authentication using known hosts authentication.

To determine how the SSH daemon\'s "IgnoreRhosts" option is set, run the following command:

# grep -i IgnoreRhosts /etc/ssh/sshd_config

IgnoreRhosts yes

If the value is returned as “no”, the returned line is commented out, or no output is returned, this is a finding.'

# START_DESCRIBE RHEL-07-040334
  describe sshd_config do
    its('IgnoreRhosts') { should eq 'yes' }
  end
# STOP_DESCRIBE RHEL-07-040334

end

