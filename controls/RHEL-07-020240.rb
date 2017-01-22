# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020240 - The operating system must be a supported release.'
control 'RHEL-07-020240' do
  impact 1.0
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  tag 'stig', 'RHEL-07-020240'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020240_chk'
  tag fixid: 'F-RHEL-07-020240_fix'
  tag version: 'RHEL-07-020240'
  tag ruleid: 'RHEL-07-020240_rule'
  tag fixtext: 'Upgrade to a supported version of the operating system.'
  tag checktext: 'Severity Override Guidance: 

Check the version of the operating system with the following command:

# cat /etc/redhat-release

Red Hat Enterprise Linux Server release 7.2 (Maipo)
Current End of Life for RHEL 7 is June 30, 2024.

If the release is not supported by the vendor, this is a finding.'

# START_DESCRIBE RHEL-07-020240
  describe file('/etc/redhat-release') do
    its('content') { should match /7\.[0-3]/ }
  end
# STOP_DESCRIBE RHEL-07-020240

end

