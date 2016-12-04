# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040540 - Remote X connections for interactive users must be encrypted.'
control 'RHEL-07-040540' do
  impact 1.0
  title 'Remote X connections for interactive users must be encrypted.'
  desc 'Open X displays allow an attacker to capture keystrokes and execute commands remotely.'
  tag 'stig', 'RHEL-07-040540'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-040540_chk'
  tag fixid: 'F-RHEL-07-040540_fix'
  tag version: 'RHEL-07-040540'
  tag ruleid: 'RHEL-07-040540_rule'
  tag fixtext: 'Configure SSH to encrypt connections for interactive users.

Edit the /etc/ssh/sshd_config file to uncomment or add the line for the X11Forwarding keyword and set its value to “yes” (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

X11Fowarding yes'
  tag checktext: 'Verify remote X connections for interactive users are encrypted.

Check that remote X connections are encrypted with the following command:

# grep -i x11forwarding /etc/ssh/sshd_config
X11Fowarding yes

If the X11Forwarding keyword is set to "no", is missing, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040540
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040540

end

