# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040181 - The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.'
control 'RHEL-07-040181' do
  impact 0.5
  title 'The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.  Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  tag 'stig', 'RHEL-07-040181'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040181_chk'
  tag fixid: 'F-RHEL-07-040181_fix'
  tag version: 'RHEL-07-040181'
  tag ruleid: 'RHEL-07-040181_rule'
  tag fixtext: 'Configure the operating system to implement cryptography to protect the integrity of LDAP remote access sessions.

Set the tls_cacertdir option in /etc/pam_ldap.conf to point to the directory that will contain the X.509 certificates for peer authentication.

Set the tls_cacertfile option in /etc/pam_ldap.conf to point to the path for the X.509 certificates used for peer authentication.'
  tag checktext: 'Verify the operating system implements cryptography to protect the integrity of remote LDAP access sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used. 

Check for the directory containing X.509 certificates for peer authentication with the following command:

# grep -i cacertdir /etc/pam_ldap.conf
tls_cacertdir /etc/openldap/certs

Verify the directory set with the “tls_cacertdir” option exists.

If the directory does not exist or the option is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040181
  ldap_auth_enabled = command('grep -i USELDAPAUTH=yes /etc/sysconfig/authconfig').exit_status
  if ldap_auth_enabled
    describe file('/etc/pam_ldap.conf') do
      its('content') { should match /^tls_cacertdir\s+\/etc\/openldap\/certs$/ }
    end

    describe file('/etc/openldap/certs') do
      it { should be_directory }
    end
  end
# STOP_DESCRIBE RHEL-07-040181

end

