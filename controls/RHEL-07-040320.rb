# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040320 - For systems using DNS resolution, at least two name servers must be configured.'
control 'RHEL-07-040320' do
  impact 0.1
  title 'For systems using DNS resolution, at least two name servers must be configured.'
  desc 'To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  tag 'stig', 'RHEL-07-040320'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-040320_chk'
  tag fixid: 'F-RHEL-07-040320_fix'
  tag version: 'RHEL-07-040320'
  tag ruleid: 'RHEL-07-040320_rule'
  tag fixtext: 'Configure the operating system to use two or more name servers for DNS resolution.

Edit the “/etc/resolv.conf” file to uncomment or add the two or more nameserver option lines with the IP address of local authoritative name servers. If local host resolution is being performed, the “/etc/resolv.conf” file must be empty. An empty “/etc/resolv.conf” file can be created as follows:

# echo -n > /etc/resolv.conf
And then make the file immutable with the following command:
# chattr +i /etc/resolv.conf'
  tag checktext: 'Determine whether the system is using local or DNS name resolution with the following command:

# grep hosts /etc/nsswitch.conf
hosts:   files dns

If the dns entry is missing from the host’s line in the “/etc/nsswitch.conf” file, the “/etc/resolv.conf” file must be empty.

Verify the “/etc/resolv.conf” file is empty with the following command:

# l s -al /etc/resolv.conf
-rw-r--r--  1 root root        0 Aug 19 08:31 resolv.conf

If local host authentication is being used and the “/etc/resolv.conf” file is not empty, this is a finding.

If the dns entry is found on the host’s line of the “/etc/nsswitch.conf” file, verify the operating system is configured to use two or more name servers for DNS resolution.

Determine the name servers used by the system with the following command:

# grep nameserver /etc/resolv.conf
nameserver 192.168.1.2
nameserver 192.168.1.3

If less than two lines are returned that are not commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040320
  describe command('if [ `grep -c "^nameserver" /etc/resolv.conf` -ge 2 ]; then exit 0; else exit 1; fi') do
    its('exit_status') { should eq 0 }
  end
# STOP_DESCRIBE RHEL-07-040320

end

