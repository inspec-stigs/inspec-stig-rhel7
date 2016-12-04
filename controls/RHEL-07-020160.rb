# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020160 - USB mass storage must be disabled.'
control 'RHEL-07-020160' do
  impact 0.5
  title 'USB mass storage must be disabled.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.  Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227'
  tag 'stig', 'RHEL-07-020160'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020160_chk'
  tag fixid: 'F-RHEL-07-020160_fix'
  tag version: 'RHEL-07-020160'
  tag ruleid: 'RHEL-07-020160_rule'
  tag fixtext: 'Configure the operating system to disable the ability to use USB mass storage devices.

Create a file under /etc/modprobe.d with the following command:

#touch /etc/modprobe.d/nousbstorage

Add the following line to the created file:

install usb-storage /bin/true'
  tag checktext: 'If there is an HBSS with a Device Control Module and a Data Loss Prevention mechanism, this requirement is not applicable.

Verify the operating system disables the ability to use USB mass storage devices.

Check to see if USB mass storage is disabled with the following command:

#grep -i usb-storage /etc/modprobe.d/*

install usb-storage /bin/true

If the command does not return any output, and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'

# START_DESCRIBE RHEL-07-020160
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020160

end

