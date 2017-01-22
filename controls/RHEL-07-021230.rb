# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-021230 - Kernel core dumps must be disabled unless needed.'
control 'RHEL-07-021230' do
  impact 0.5
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.'
  tag 'stig', 'RHEL-07-021230'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-021230_chk'
  tag fixid: 'F-RHEL-07-021230_fix'
  tag version: 'RHEL-07-021230'
  tag ruleid: 'RHEL-07-021230_rule'
  tag fixtext: 'If kernel core dumps are not required, disable the “kdump” service with the following command:

# systemctl disable kdump.service

If kernel core dumps are required, document the need with the ISSM.'
  tag checktext: 'Verify that kernel core dumps are disabled unless needed.

Check the status of the “kdump” service with the following command:

# systemctl status kdump.service
kdump.service - Crash recovery kernel arming
   Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled)
   Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago
 Main PID: 1130 (code=exited, status=0/SUCCESS)
kernel arming.

If the “kdump” service is active, ask the System Administrator (SA) if the use of the service is required and documented with the Information System Security Manager (ISSM).

If the service is active and is not documented, this is a finding.'

# START_DESCRIBE RHEL-07-021230
  describe service('kdump') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
# STOP_DESCRIBE RHEL-07-021230

end

