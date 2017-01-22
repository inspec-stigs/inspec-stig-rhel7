# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040620 - The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
control 'RHEL-07-040620' do
  impact 0.5
  title 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA.'
  tag 'stig', 'RHEL-07-040620'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040620_chk'
  tag fixid: 'F-RHEL-07-040620_fix'
  tag version: 'RHEL-07-040620'
  tag ruleid: 'RHEL-07-040620_rule'
  tag fixtext: 'Edit the /etc/ssh/sshd_config file to uncomment or add the line for the MACs keyword and set its value to “hmac-sha2-256” and/or “hmac-sha2-512 “(this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

MACs hmac-sha2-256,hmac-sha2-512'
  tag checktext: 'Verify the SSH daemon is configured to only use MACs employing FIPS 140-2 approved ciphers.

Note: If RHEL-07-021280 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

Check that the SSH daemon is configured to only use MACs employing FIPS 140-2 approved ciphers with the following command:

# grep -i macs /etc/ssh/sshd_config
MACs hmac-sha2-256,hmac-sha2-512

If any ciphers other than “hmac-sha2-256” or “hmac-sha2-512” are listed or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040620
  describe sshd_config do
    its('MACs') { should eq 'hmac-sha2-256,hmac-sha2-512' }
  end
# STOP_DESCRIBE RHEL-07-040620

end
