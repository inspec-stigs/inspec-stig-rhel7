# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021280 - The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
control 'RHEL-07-021280' do
  impact 1.0
  title 'The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.  Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000396-GPOS-00176, SRG-OS-000478-GPOS-00223'
  tag 'stig', 'RHEL-07-021280'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-021280_chk'
  tag fixid: 'F-RHEL-07-021280_fix'
  tag version: 'RHEL-07-021280'
  tag ruleid: 'RHEL-07-021280_rule'
  tag fixtext: 'Configure the operating system to implement DoD-approved encryption by installing the dracut-fips package.

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Placing a system into FIPS mode after system creation involves a number of modifications to the GRUB2 configuration that are not trivial to implement.'
  tag checktext: 'Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if the dracut-fips package is installed with the following command:

# yum list installed | grep dracut-fips

dracut-fips-033-360.el7_2.x86_64.rpm

If the dracut-fips package is installed, check to see if the kernel command line is configured to use FIPS mode with the following command:

Note: GRUB 2 reads its configuration from the “/boot/grub2/grub.cfg” file on traditional BIOS-based machines and from the “/boot/efi/EFI/redhat/grub.cfg” file on UEFI machines.

#grep fips /boot/grub2/grub.cfg
/vmlinuz-3.8.0-0.40.el7.x86_64 root=/dev/mapper/rhel-root ro rd.md=0 rd.dm=0 rd.lvm.lv=rhel/swap crashkernel=auto rd.luks=0 vconsole.keymap=us rd.lvm.lv=rhel/root rhgb fips=1 quiet

If the kernel command line is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

# cat /proc/sys/crypto/fips_enabled 1

If the dracut-fips package is not installed, the kernel command line does not have a fips entry, or the system has a value of “0” for fips_enabled in /proc/sys/crypto, this is a finding.'

# START_DESCRIBE RHEL-07-021280
  describe package('dracut-fips') do
    it { should be_installed }
  end

  describe file('/proc/sys/crypto/fips_enabled') do
    its('content') { should match /^1/ }
  end

  grub_cfg_exists = file('/boot/grub2/grub.cfg').file?
  if grub_cfg_exists
    describe file('/boot/grub2/grub.cfg') do
      its('content') { should match /fips=1/ }
    end
  end

  grub_uefi_cfg_exists = file('/boot/efi/EFI/redhat/grub.cfg').file?
  if grub_uefi_cfg_exists
    describe file('/boot/efi/EFI/redhat/grub.cfg') do
      its('content') { should match /fips=1/ }
    end
  end
# STOP_DESCRIBE RHEL-07-021280

end

