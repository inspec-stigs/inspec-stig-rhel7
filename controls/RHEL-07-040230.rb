# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040230 - The operating system, if using PKI-based authentication, must implement a local cache of revocation data to certificate validation in case of the inability to access revocation information via the network.'
control 'RHEL-07-040230' do
  impact 0.5
  title 'The operating system, if using PKI-based authentication, must implement a local cache of revocation data to certificate validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  tag 'stig', 'RHEL-07-040230'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040230_chk'
  tag fixid: 'F-RHEL-07-040230_fix'
  tag version: 'RHEL-07-040230'
  tag ruleid: 'RHEL-07-040230_rule'
  tag fixtext: 'Configure the operating system, for PKI-based authentication, to implement a local cache of revocation data to support certificate validation in case of the inability to access revocation information via the network.

Add the following lines to /var/lib/pki-kra/conf/server.xml (or modify the line to have the required value):

auths.revocationChecking.bufferSize=50
auths.revocationChecking.enabled=true

Add the following lines to /var/lib/pki-kra/conf/server.xml (or modify the line to have the required value):

enableOCSP="true"
ocspCacheSize="50"'
  tag checktext: 'Verify the operating system, for PKI-based authentication, implements a local cache of revocation data to support certificate validation in case of the inability to access revocation information via the network.

Check to see if the certificate authority certificate revocation data cache is enabled on the system with the following command:

# grep -i  revocationchecking /var/lib/pki-ca/conf/CS.cfg
auths.revocationChecking.bufferSize=50
auths.revocationChecking.ca=ca
auths.revocationChecking.enabled=true
auths.revocationChecking.unknownStateInterval=0
auths.revocationChecking.validityInterval=120

If auths.revocationChecking.enabled is not set to "true", this is a finding.

If auths.revocationChecking.bufferSize is not set to a value of “50” or less, this is a finding.

Check to see if the Online Certificate Status Protocol (OCSP) certificate revocation data cache is enabled on the system with the following command: 

# grep -i ocsp /var/lib/pki-kra/conf/server.xml
enableOCSP="true"
ocspResponderURL="http://server.pki.mil:9180/ca/ocsp"
      ocspResponderCertNickname="ocspSigningCert cert-pki-ca 102409a"
        ocspCacheSize="50"
        ocspMinCacheEntryDuration="60"
        ocspMaxCacheEntryDuration="120"
        ocspTimeout="10"

If “enableOCSP” is not set to "true", this is a finding.

If “ocspCacheSize” is not set to a value of “50” or less, this is a finding.'

# START_DESCRIBE RHEL-07-040230
  cs_cfg_exists = file('/var/lib/pki-ca/conf/CS.cfg').file?
  if cs_cfg_exists
    describe file('/var/lib/pki-ca/conf/CS.cfg') do
      its('content') { should match /^auths.revocationChecking.enabled=true$/ }
      its('content') { should match /^auths.revocationChecking.bufferSize=([0-9]|[0-4][0-9]|50)$/ }
    end
  end
# STOP_DESCRIBE RHEL-07-040230

end

