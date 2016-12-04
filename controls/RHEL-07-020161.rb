# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020161 - File system automounter must be disabled unless required.'
control 'RHEL-07-020161' do
  impact 0.5
  title 'File system automounter must be disabled unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.  Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227'
  tag 'stig', 'RHEL-07-020161'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020161_chk'
  tag fixid: 'F-RHEL-07-020161_fix'
  tag version: 'RHEL-07-020161'
  tag ruleid: 'RHEL-07-020161_rule'
  tag fixtext: 'Configure the operating system to disable the ability to automount devices.

Turn off the automount service with the following command:

# systemctl disable autofs

If “autofs” is required for Network File System (NFS), it must be documented with the ISSO.'
  tag checktext: 'Verify the operating system disables the ability to automount devices.

Check to see if automounter service is active with the following command:

# systemctl status autofs
autofs.service - Automounts filesystems on demand
   Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
   Active: inactive (dead)

If the “autofs” status is set to “active” and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'

# START_DESCRIBE RHEL-07-020161
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020161

end

