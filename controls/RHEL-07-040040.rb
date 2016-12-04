# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040040 - The operating system, for PKI-based authentication, must enforce authorized access to all PKI private keys stored or used by the operating system.'
control 'RHEL-07-040040' do
  impact 0.5
  title 'The operating system, for PKI-based authentication, must enforce authorized access to all PKI private keys stored or used by the operating system.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.  The cornerstone of the PKI is the private key used to encrypt or digitally sign information.  If private keys are stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key(s) to digitally sign data and thus impersonate the associated subjects (systems or users).  Both the holders of a digital certificate and the issuing authority must take careful measures to protect the corresponding private keys. Private keys should always be generated and protected in appropriate FIPS 140-2 validated cryptographic modules.'
  tag 'stig', 'RHEL-07-040040'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040040_chk'
  tag fixid: 'F-RHEL-07-040040_fix'
  tag version: 'RHEL-07-040040'
  tag ruleid: 'RHEL-07-040040_rule'
  tag fixtext: 'Configure the operating system, for PKI-based authentication, to enforce authorized access to all PKI private keys stored or used by the operating system.

To use cackey edit /etc/pam_pkcs11/pam_pkcs11.conf:

Change the use_pkcs11_module option to cackey.
use_pkcs11_module = cackey;

Then directly after the aforementioned line, copy the following lines:

# Cackey Support
  pkcs11_module cackey {
    module = /usr/lib64/libcackey.so;
    description = "Cackey";
    slot_num = 0;
    support_threads = false;
    ca_dir = /etc/pam_pkcs11/cacerts;
    crl_dir = /etc/pam_pkcs11/crls;
    cert_policy = signature;
  }
To use coolkey edit /etc/pam_pkcs11/pam_pkcs11.conf:

Change the use_pkcs11_module option to coolkey.
use_pkcs11_module = coolkey;

Then directly after the aforementioned line, copy the following lines:

# Cackey Support
  pkcs11_module coolkey {
    module = libcoolkeypk11.so;

    description = "Coolkey";
    slot_num = 0;
    support_threads = false;
    ca_dir = “/etc/pam_pkcs11/cacerts”;
    crl_dir = “/etc/pam_pkcs11/crls”;
    cert_policy = signature;
  }

Find and change the line:

use_mappers = digest, cn, pwent, uid, mail, subject, null;
to
use_mappers = subject;'
  tag checktext: 'Verify the operating system, for PKI–based authentication, enforces authorized access to all PKI private keys stored/utilized by the operating system.

Check the module being used by the system smartcard architecture with the following command:

# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf
use_pkcs11_module = cackey; 

If the module returned is not cackey or coolkey, or the line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040040
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040040

end

