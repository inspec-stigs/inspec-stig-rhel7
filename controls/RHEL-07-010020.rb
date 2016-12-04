# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010020 - The cryptographic hash of system files and commands must match vendor values.'
control 'RHEL-07-010020' do
  impact 1.0
  title 'The cryptographic hash of system files and commands must match vendor values.'
  desc 'Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection.  Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  tag 'stig', 'RHEL-07-010020'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-010020_chk'
  tag fixid: 'F-RHEL-07-010020_fix'
  tag version: 'RHEL-07-010020'
  tag ruleid: 'RHEL-07-010020_rule'
  tag fixtext: 'Run the following command to determine which package owns the file:

# rpm -qf <filename>

The package can be reinstalled from a yum repository using the command:

# sudo yum reinstall <packagename>

Alternatively, the package can be reinstalled from trusted media using the command:

# sudo rpm -Uvh <packagename>'
  tag checktext: 'Verify the cryptographic hash of system files and commands match the vendor values.

Check the cryptographic hash of system files and commands with the following command:

Note: System configuration files (indicated by a "c" in the second column) are expected to change over time. Unusual modifications should be investigated through the system audit log.

# rpm -Va | grep \'^..5\'

If there is any output from the command for system binaries, this is a finding.'

# START_DESCRIBE RHEL-07-010020
if os[:family] == 'redhat'
  describe command("rpm -Va | grep '^..5'") do
    its('stdout') { should eq '' }
  end
end

# STOP_DESCRIBE RHEL-07-010020

end

