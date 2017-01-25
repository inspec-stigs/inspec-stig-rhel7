# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021760 - The system must not allow removable media to be used as the boot loader unless approved.'
control 'RHEL-07-021760' do
  impact 0.5
  title 'The system must not allow removable media to be used as the boot loader unless approved.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO).'
  tag 'stig', 'RHEL-07-021760'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021760_chk'
  tag fixid: 'F-RHEL-07-021760_fix'
  tag version: 'RHEL-07-021760'
  tag ruleid: 'RHEL-07-021760_rule'
  tag fixtext: 'Remove alternate methods of booting the system from removable media or document the configuration to boot from removable media with the ISSO.'
  tag checktext: 'Verify the system is not configured to use a boot loader on removable media.

Note: GRUB 2 reads its configuration from the “/boot/grub2/grub.cfg” file on traditional BIOS-based machines and from the “/boot/efi/EFI/redhat/grub.cfg” file on UEFI machines.

Check for the existence of alternate boot loader configuration files with the following command:

# find / -name grub.conf
/boot/grub2/grub.cfg

If a “grub.cfg” is found in any subdirectories other than “/boot/grub2” and “/boot/efi/EFI/redhat”, ask the System Administrator (SA) if there is documentation signed by the ISSO to approve the use of removable media as a boot loader. 

Check that the grub configuration file has the set root command in each menu entry with the following commands:

# grep -c menuentry /boot/grub2/grub.cfg
1
# grep ‘set root’ /boot/grub2/grub.cfg
set root=(hd0,1)

If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding.'

# START_DESCRIBE RHEL-07-021760
  describe.one do
    describe file('/boot/grub2/grub.cfg') do
      its('content') { should match /set\s+root=/ }
    end

    describe file('/boot/efi/EFI/redhat/grub.cfg') do
      its('content') { should match /set\s+root=/ }
    end
  end
# STOP_DESCRIBE RHEL-07-021760

end

