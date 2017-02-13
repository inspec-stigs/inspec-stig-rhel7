# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010460 - Systems with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes.'
control 'RHEL-07-010460' do
  impact 1.0
  title 'Systems with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  tag 'stig', 'RHEL-07-010460'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010460_chk'
  tag fixid: 'F-RHEL-07-010460_fix'
  tag version: 'RHEL-07-010460'
  tag ruleid: 'RHEL-07-010460_rule'
  tag fixtext: 'Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.

# grub-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45

Using this hash, modify the “/etc/grub.d/10_linux” file with the following commands to add the password to the root entry:

# cat << EOF
> set superusers="root" password_pbkdf2 smithj grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45
> EOF

Generate a new grub.conf file with the new password with the following commands:

# grub2-mkconfig --output=/tmp/grub2.cfg
# mv /tmp/grub2.cfg /boot/grub2/grub.cfgirement'
  tag checktext: 'Check to see if an encrypted root password is set. On systems that use a BIOS, use the following command:

# grep -i password /boot/grub2/grub.cfg
password_pbkdf2 superusers-account password-hash

If the root password entry does not begin with “password_pbkdf2”, this is a finding.'

# START_DESCRIBE RHEL-07-010460
  grub_cfg_exists = file('/boot/grub2/grub.cfg').file?
  if grub_cfg_exists
    describe file('/boot/grub2/grub.cfg') do
      its('content') { should match /^\s*password_pbkdf2\s+superusers-account\s+password-hash/ }
    end
  end
# STOP_DESCRIBE RHEL-07-010460

end

