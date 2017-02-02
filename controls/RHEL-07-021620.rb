# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021620 - The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.'
control 'RHEL-07-021620' do
  impact 0.5
  title 'The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.'
  desc 'File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2 approved cryptographic hashes.'
  tag 'stig', 'RHEL-07-021620'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021620_chk'
  tag fixid: 'F-RHEL-07-021620_fix'
  tag version: 'RHEL-07-021620'
  tag ruleid: 'RHEL-07-021620_rule'
  tag fixtext: 'Configure the file integrity tool to use FIPS 140-2 cryptographic hashes for validating file and directory contents. If AIDE is installed, ensure the “sha512” rule is present on all file and directory selection lists.'
  tag checktext: 'Verify the file integrity tool is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.

Note: If RHEL-07-021280 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:

# yum list installed | grep aide

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

Note: AIDE is highly configurable at install time. These commands assume the “aide.conf” file is under the “/etc directory”. 

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the “aide.conf” file to determine if the “sha512” rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the sha512 rule follows:

All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin 
/sbin All          # apply the same custom rule to the files in sbin 

If the “sha512” rule is not being used on all selection lines in the “/etc/aide.conf” file, or another file integrity tool is not using FIPS 140-2 approved cryptographic hashes for validating file contents and directories, this is a finding.'

# START_DESCRIBE RHEL-07-021620
  describe package('aide') do
    it { should be_installed }
  end

  describe file('/etc/aide.conf') do
    its('content') { should match /^(?!#).*\s*=\s*.*sha512.*$/ }
  end
# STOP_DESCRIBE RHEL-07-021620

end

