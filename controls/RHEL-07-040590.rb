# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040590 - The SSH daemon must be configured to only use the SSHv2 protocol.'
control 'RHEL-07-040590' do
  impact 1.0
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.  Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227'
  tag 'stig', 'RHEL-07-040590'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-040590_chk'
  tag fixid: 'F-RHEL-07-040590_fix'
  tag version: 'RHEL-07-040590'
  tag ruleid: 'RHEL-07-040590_rule'
  tag fixtext: 'Remove all Protocol lines that reference version 1 in /etc/ssh/sshd_config (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). The "Protocol" line must be as follows:

Protocol 2'
  tag checktext: 'Verify the SSH daemon is configured to only use the SSHv2 protocol.

Check that the SSH daemon is configured to only use the SSHv2 protocol with the following command:

# grep -i protocol /etc/ssh/sshd_config
Protocol 2
#Protocol 1,2

If any protocol line other than "Protocol 2" is uncommented, this is a finding.'

# START_DESCRIBE RHEL-07-040590
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040590

end

