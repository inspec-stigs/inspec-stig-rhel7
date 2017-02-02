# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040690 - The SSH daemon must use privilege separation.'
control 'RHEL-07-040690' do
  impact 0.5
  title 'The SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  tag 'stig', 'RHEL-07-040690'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040690_chk'
  tag fixid: 'F-RHEL-07-040690_fix'
  tag version: 'RHEL-07-040690'
  tag ruleid: 'RHEL-07-040690_rule'
  tag fixtext: 'Uncomment the “UsePrivilegeSeparation” keyword in /etc/ssh/sshd_config (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "yes":

UsePrivilegeSeparation yes'
  tag checktext: 'Verify the SSH daemon performs privilege separation.

Check that the SSH daemon performs privilege separation with the following command:

# grep -i usepriv /etc/ssh/sshd_config
UsePrivilegeSeparation yes

If the “UsePrivilegeSeparation” keyword is set to "no", is missing, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040690
  describe sshd_config do
    its('UsePrivilegeSeparation') { should eq 'yes' }
  end
# STOP_DESCRIBE RHEL-07-040690

end

