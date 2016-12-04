# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040650 - The SSH private host key files must have mode 0600 or less permissive.'
control 'RHEL-07-040650' do
  impact 0.5
  title 'The SSH private host key files must have mode 0600 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  tag 'stig', 'RHEL-07-040650'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040650_chk'
  tag fixid: 'F-RHEL-07-040650_fix'
  tag version: 'RHEL-07-040650'
  tag ruleid: 'RHEL-07-040650_rule'
  tag fixtext: 'Configure the mode of SSH private host key files under “/etc/ssh” to “0600” with the following command:

# chmod 0600 /etc/ssh/ssh_host*key'
  tag checktext: 'Verify the SSH private host key files have mode “0600” or less permissive.

The following command will find all SSH private key files on the system:

# find / -name \'*ssh_host*key\'

Check the mode of the private host key files under /etc/ssh file with the following command:

# ls -lL /etc/ssh/*key
-rw-------  1 root  wheel  668 Nov 28 06:43 ssh_host_dsa_key
-rw-------  1 root  wheel  582 Nov 28 06:43 ssh_host_key
-rw-------  1 root  wheel  887 Nov 28 06:43 ssh_host_rsa_key

If any file has a mode more permissive than “0600”, this is a finding.'

# START_DESCRIBE RHEL-07-040650
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040650

end

