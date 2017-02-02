# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040050 - The operating system must map the authenticated identity to the user or group account for PKI-based authentication.'
control 'RHEL-07-040050' do
  impact 0.5
  title 'The operating system must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  tag 'stig', 'RHEL-07-040050'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040050_chk'
  tag fixid: 'F-RHEL-07-040050_fix'
  tag version: 'RHEL-07-040050'
  tag ruleid: 'RHEL-07-040050_rule'
  tag fixtext: 'Configure the operating system to map the authenticated identity to the user or group account for PKI-based authentication by creating the common name map file with the following command:

# touch /etc/pam_pkcs11/subject_mapping'
  tag checktext: 'Verify the operating system maps the authenticated identity to the user or group account for PKI–based authentication by verifying the common name map file exists with the following command:

# ls –al /etc/pam_pkcs11/cn_map
–rw–r––––– 1 root root 1294 Apr 22 17:22 /etc/pam_pkcs11/subject_mapping

If the file does not exist, this is a finding.'

# START_DESCRIBE RHEL-07-040050
  is_pam_pkcs11_installed = package('pam_pkcs11').installed?
  if is_pam_pkcs11_installed
    describe file('/etc/pam_pkcs11/subject_mapping') do
      it { should exist }
    end
  end
# STOP_DESCRIBE RHEL-07-040050

end

