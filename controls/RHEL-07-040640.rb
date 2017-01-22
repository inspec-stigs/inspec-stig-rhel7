# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040640 - The SSH public host key files must have mode 0644 or less permissive.'
control 'RHEL-07-040640' do
  impact 0.5
  title 'The SSH public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  tag 'stig', 'RHEL-07-040640'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040640_chk'
  tag fixid: 'F-RHEL-07-040640_fix'
  tag version: 'RHEL-07-040640'
  tag ruleid: 'RHEL-07-040640_rule'
  tag fixtext: 'Note: SSH public key files may be found in other directories on the system depending on the installation. 

The following command will find all SSH public key files on the system:

# find / -name ‘*key.pub’

Change the mode of public host key files under “/etc/ssh” to “0644” with the following command:

# chmod 0644 /etc/ssh/*.key.pub'
  tag checktext: 'Verify the SSH public host key files have mode “0644” or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation.

The following command will find all SSH public key files on the system:

# find / -name \'*.pub\'

Check the mode of the public host key files under /etc/ssh file with the following command:

# ls -lL /etc/ssh/*.pub
-rw-r--r--  1 root  wheel  618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r--  1 root  wheel  347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r--  1 root  wheel  238 Nov 28 06:43 ssh_host_rsa_key.pub

If any file has a mode more permissive than “0644”, this is a finding.'

# START_DESCRIBE RHEL-07-040640
  pub_keys = command('find / -name "*.pub"').stdout.split("\n")
  for pub_key in pub_keys do
    describe.one do
      describe file(pub_key) do
        its('mode') { should cmp '0644' }
      end

      describe file(pub_key) do
        its('mode') { should cmp '0640' }
      end

      describe file(pub_key) do
        its('mode') { should cmp '0600' }
      end
    end
  end
# STOP_DESCRIBE RHEL-07-040640

end

