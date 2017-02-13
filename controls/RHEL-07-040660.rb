# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040660 - The SSH daemon must not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.'
control 'RHEL-07-040660' do
  impact 0.5
  title 'The SSH daemon must not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed.'
  tag 'stig', 'RHEL-07-040660'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040660_chk'
  tag fixid: 'F-RHEL-07-040660_fix'
  tag version: 'RHEL-07-040660'
  tag ruleid: 'RHEL-07-040660_rule'
  tag fixtext: 'Uncomment the “GSSAPIAuthentication” keyword in /etc/ssh/sshd_config (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "no": 

GSSAPIAuthentication no

If GSSAPI authentication is required, it must be documented, to include the location of the configuration file, with the ISSO.'
  tag checktext: 'Verify the SSH daemon does not permit GSSAPI authentication unless approved.

Check that the SSH daemon does not permit GSSAPI authentication with the following command:

# grep -i gssapiauth /etc/ssh/sshd_config
GSSAPIAuthentication no

If the “GSSAPIAuthentication” keyword is missing, is set to “yes” and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040660
  describe sshd_config do
    its('GSSAPIAuthentication') { should eq 'no' }
  end
# STOP_DESCRIBE RHEL-07-040660

end

