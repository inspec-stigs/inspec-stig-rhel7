# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040110 - A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications.'
control 'RHEL-07-040110' do
  impact 0.5
  title 'A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.  Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.  FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.  Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000120-GPOS-00061, SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173'
  tag 'stig', 'RHEL-07-040110'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040110_chk'
  tag fixid: 'F-RHEL-07-040110_fix'
  tag version: 'RHEL-07-040110'
  tag ruleid: 'RHEL-07-040110_rule'
  tag fixtext: 'Configure SSH to use FIPS 140-2 approved cryptographic algorithms.

Add the following line (or modify the line to have the required value) to the /etc/ssh/sshd_config file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

Ciphers aes128-ctr aes192-ctr, aes256-ctr'
  tag checktext: 'Verify the operating system uses mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

Note: If RHEL-07-021280 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

The location of the sshd_config file may vary on the system and can be found using the following command:

# find / -name ‘sshd*_config’

If there is more than one ssh server daemon configuration file on the system, determine which daemons are active on the system with the following command:

# ps -ef | grep sshd

The command will return the full path of the ssh daemon. This will indicate which sshd_config file will be checked with the following command:

# grep -i ciphers /etc/ssh/sshd_config
Ciphers aes128-ctr aes192-ctr, aes256-ctr

If any ciphers other than “aes128-ctr”, “aes192-ctr”, or “aes256-ctr” are listed, the “Ciphers” keyword is missing, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040110
  describe sshd_config do
    its('Ciphers') { should eq 'aes128-ctr,aes192-ctr,aes256-ctr' }
  end
# STOP_DESCRIBE RHEL-07-040110

end

