# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040030 - The operating system, for PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
control 'RHEL-07-040030' do
  impact 0.5
  title 'The operating system, for PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc 'A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.    When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.  Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.   Operating systems that do not validate certificates by performing RFC 5280-compliant certification path validation to a trust anchor are in danger of accepting certificates that are invalid and or counterfeit. This could allow unauthorized access to a system.'
  tag 'stig', 'RHEL-07-040030'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040030_chk'
  tag fixid: 'F-RHEL-07-040030_fix'
  tag version: 'RHEL-07-040030'
  tag ruleid: 'RHEL-07-040030_rule'
  tag fixtext: 'Configure the operating system, for PKI-based authentication, to validate certificates by performing RFC 5280-compliant certification path validation.

Set all cert_policy lines to use Online Certificate Status Protocol (OCSP) in /etc/pam_pkcs11/pam_pkcs11.conf:

cert_policy = ca, ocsp_on, signature;

If the system cannot use OCSP, configure the system to use certificate revocation lists in /etc/pam_pkcs11/ pam_pkcs11.conf:

crl_dir = /etc/pam_pkcs11/crls;

and place a certificate revocation file in the configured directory.'
  tag checktext: 'Verify the operating system, for PKI–based authentication, validates certificates by performing RFC 5280–compliant certification path validation.

Check to see if Online Certificate Status Protocol (OCSP) is enabled on the system with the following command:

# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf
cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;

There must be at least three lines returned. If oscp_on is present in all cert_policy lines this is not a finding.

If oscp_on is not present in all lines check for the presence of certificate revocation lists:

# grep crl_dir = /etc/pam_pkcs11/crls
crl_dir = /etc/pam_pkcs11/crls;

Check the returned directory for the presence of a crl file.

If the file exists this in the configured directory is not a finding.

If the system is not configured to use OCSP or crls, or the crls file is missing, this is a finding.'

# START_DESCRIBE RHEL-07-040030
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040030

end

