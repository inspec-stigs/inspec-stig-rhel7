# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040310 - The system must not permit direct logons to the root account using remote access via SSH.'
control 'RHEL-07-040310' do
  impact 0.5
  title 'The system must not permit direct logons to the root account using remote access via SSH.'
  desc 'Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.'
  tag 'stig', 'RHEL-07-040310'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040310_chk'
  tag fixid: 'F-RHEL-07-040310_fix'
  tag version: 'RHEL-07-040310'
  tag ruleid: 'RHEL-07-040310_rule'
  tag fixtext: 'Configure SSH to stop users from logging on remotely as the root user.

Edit the appropriate  /etc/ssh/sshd_config file to uncomment or add the line for the PermitRootLogin keyword and set its value to “no” (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

PermitRootLogin no'
  tag checktext: 'Verify remote access using SSH prevents users from logging on directly as root.

Check that SSH prevents users from logging on directly as root with the following command:

# grep -i permitrootlogin /etc/ssh/sshd_config
PermitRootLogin no

If the “PermitRootLogin” keyword is set to “yes”, is missing, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040310
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040310

end

