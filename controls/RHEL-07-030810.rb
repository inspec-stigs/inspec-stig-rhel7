# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030810 - The system must use a DoD-approved virus scan program.'
control 'RHEL-07-030810' do
  impact 1.0
  title 'The system must use a DoD-approved virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.    The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.  If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  tag 'stig', 'RHEL-07-030810'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-030810_chk'
  tag fixid: 'F-RHEL-07-030810_fix'
  tag version: 'RHEL-07-030810'
  tag ruleid: 'RHEL-07-030810_rule'
  tag fixtext: 'Install an approved DoD antivirus solution on the system.'
  tag checktext: 'Verify the system is using a DoD-approved virus scan program.

Check for the presence of “McAfee VirusScan Enterprise for Linux” with the following command:

# systemctl status nails
nails - service for McAfee VirusScan Enterprise for Linux 
>  Loaded: loaded /opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>; enabled)
>  Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago

If the “nails” service is not active, check for the presence of “clamav” on the system with the following command:

# systemctl status clamav-daemon.socket
 systemctl status clamav-daemon.socket
  clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon
     Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)
     Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago

If neither of these applications are loaded and active, ask the System Administrator (SA) if there is an antivirus package installed and active on the system. If no antivirus scan program is active on the system, this is a finding.'

# START_DESCRIBE RHEL-07-030810
  describe.one do
    describe service('nails') do
      it { should be_running }
      it { should be_enabled }
    end

    describe service('clamav-daemon') do
      it { should be_running }
      it { should be_enabled }
    end
  end
# STOP_DESCRIBE RHEL-07-030810

end

