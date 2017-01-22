# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030820 - The system must update the DoD-approved virus scan program every seven days or more frequently.'
control 'RHEL-07-030820' do
  impact 0.5
  title 'The system must update the DoD-approved virus scan program every seven days or more frequently.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.    The virus scanning software should be configured to check for software and virus definition updates with a frequency no longer than seven days. If a manual process is required to update the virus scan software or definitions, it must be documented with the Information System Security Manager (ISSM).'
  tag 'stig', 'RHEL-07-030820'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030820_chk'
  tag fixid: 'F-RHEL-07-030820_fix'
  tag version: 'RHEL-07-030820'
  tag ruleid: 'RHEL-07-030820_rule'
  tag fixtext: 'Update the approved DoD virus scan software and virus definition files.'
  tag checktext: 'Verify the system is using a DoD-approved virus scan program and the virus definition file is less than seven days old.

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

If “McAfee VirusScan Enterprise for Linux” is active on the system, check the dates of the virus definition files with the following command:

# ls -al /opt/NAI/LinuxShield/engine/dat/*.dat
<need output>

If the virus definition files have dates older than seven days from the current date, this is a finding.

If “clamav” is active on the system, check the dates of the virus database with the following commands:

# grep -I databasedirectory /etc/clamav.conf
DatabaseDirectory /var/lib/clamav

# ls -al /var/lib/clamav/*.cvd
-rwxr-xr-x  1 root root      149156 Mar  5  2011 daily.cvd

If the database file has a date older than seven days from the current date, this is a finding.'

# START_DESCRIBE RHEL-07-030820
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

  is_nails_running = package('nails').installed?
  if is_nails_running
    describe command('find /opt/NAI/LinuxShield/engine/dat/*.dat -mtime -7') do
      its('stdout') { should match /\/opt\/NAI\/LinuxShield\/engine\/dat/ }
      its('exit_status') { should eq 0 }
    end
  end

  is_clamav_running = package('clamav').installed?
  if is_clamav_running
    describe command('find /var/lib/clamav/*.cvd -mtime -7') do
      its('stdout') { should match /\/var\/lib\/clamav/ }
      its('exit_status') { should eq 0 }
    end
  end
# STOP_DESCRIBE RHEL-07-030820

end

