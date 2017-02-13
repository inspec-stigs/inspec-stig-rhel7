# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040182 - The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.'
control 'RHEL-07-040182' do
  impact 0.5
  title 'The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.  Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  tag 'stig', 'RHEL-07-040182'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040182_chk'
  tag fixid: 'F-RHEL-07-040182_fix'
  tag version: 'RHEL-07-040182'
  tag ruleid: 'RHEL-07-040182_rule'
  tag fixtext: 'Configure the operating system to implement cryptography to protect the integrity of LDAP remote access sessions.

Set the tls_cacertfile option in /etc/pam_ldap.conf to point to the path for the X.509 certificates used for peer authentication.'
  tag checktext: 'Verify the operating system implements cryptography to protect the integrity of remote ldap access sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used.

Check that the path to the X.509 certificate for peer authentication with the following command:

# grep -i cacertfile /etc/pam_ldap.conf
tls_cacertfile /etc/openldap/ldap-cacert.pem

Verify the “tls_cacertfile” option points to a file that contains the trusted CA certificate.

If this file does not exist, or the option is commented out or missing, this is a finding.'

# START_DESCRIBE RHEL-07-040182
  ldap_auth_enabled = command('grep -i USELDAPAUTH=yes /etc/sysconfig/authconfig').exit_status
  if ldap_auth_enabled == 0
    describe file('/etc/pam_ldap.conf') do
      its('content') { should match /^tls_cacertfile\s+.*\.pem$/ }
    end
  end
# STOP_DESCRIBE RHEL-07-040182

end

