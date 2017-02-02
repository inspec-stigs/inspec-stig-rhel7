# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040670 - The SSH daemon must not permit Kerberos authentication unless needed.'
control 'RHEL-07-040670' do
  impact 0.5
  title 'The SSH daemon must not permit Kerberos authentication unless needed.'
  desc 'Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system\'s Kerberos implementation. Vulnerabilities in the system\'s Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability.'
  tag 'stig', 'RHEL-07-040670'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040670_chk'
  tag fixid: 'F-RHEL-07-040670_fix'
  tag version: 'RHEL-07-040670'
  tag ruleid: 'RHEL-07-040670_rule'
  tag fixtext: 'Uncomment the “KerberosAuthentication” keyword in /etc/ssh/sshd_config (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "no":

KerberosAuthentication no

If Kerberos authentication is required, it must be documented, to include the location of the configuration file, with the ISSO.'
  tag checktext: 'Verify the SSH daemon does not permit Kerberos to authenticate passwords unless approved.

Check that the SSH daemon does not permit Kerberos to authenticate passwords with the following command:

# grep -i kerberosauth /etc/ssh/sshd_config
KerberosAuthentication no

If the “KerberosAuthentication” keyword is missing, or is set to "yes" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040670
  describe sshd_config do
    its('KerberosAuthentication') { should eq 'no' }
  end
# STOP_DESCRIBE RHEL-07-040670

end

