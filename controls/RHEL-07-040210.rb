# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040210 - The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
control 'RHEL-07-040210' do
  impact 0.5
  title 'The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.  Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.  Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).  Satisfies: SRG-OS-000355-GPOS-00143, SRG-OS-000355-GPOS-00144'
  tag 'stig', 'RHEL-07-040210'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040210_chk'
  tag fixid: 'F-RHEL-07-040210_fix'
  tag version: 'RHEL-07-040210'
  tag ruleid: 'RHEL-07-040210_rule'
  tag fixtext: 'Edit the "/etc/ntp.conf" file and add or update an entry to define "maxpoll" to "10" as follows:

maxpoll 10

If NTP was running and "maxpoll" was updated, the ntp service must be restarted:

# systemctl restart ntpd

If NTP was not running, it must be started:

# systemctl start ntpd'
  tag checktext: 'Check to see if ntp is running in continuous mode.

# ps -ef | grep ntp

If NTP is not running, this is a finding.

If the process is found, then check the ntp.conf file for the “maxpoll” option setting:

# grep maxpoll /etc/ntp.conf
maxpoll 10

If the file does not exist, this is a finding.

If the option is set to “17” or is not set, this is a finding.'

# START_DESCRIBE RHEL-07-040210
  describe file('/etc/ntp.conf') do
    its('content') { should match /^maxpoll\s+10$/ }
  end
# STOP_DESCRIBE RHEL-07-040210

end

