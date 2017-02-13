# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040490 - A File Transfer Protocol (FTP) server package must not be installed unless needed.'
control 'RHEL-07-040490' do
  impact 1.0
  title 'A File Transfer Protocol (FTP) server package must not be installed unless needed.'
  desc 'The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.'
  tag 'stig', 'RHEL-07-040490'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-040490_chk'
  tag fixid: 'F-RHEL-07-040490_fix'
  tag version: 'RHEL-07-040490'
  tag ruleid: 'RHEL-07-040490_rule'
  tag fixtext: 'Document the "lftpd" package with the ISSO as an operational requirement or remove it from the system with the following command:

# yum remove lftpd'
  tag checktext: 'Verify a lightweight FTP server has not been installed on the system.

Check to see if a lightweight FTP server has been installed with the following commands:

# yum list installed | grep lftpd
 lftp-4.4.8-7.el7.x86_64.rpm

An alternate method of determining if a lightweight FTP server is active on the server is to use the following command:

# netstat -a | grep 21

If “lftpd” is installed, or if an application is listening on port 21, and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'

# START_DESCRIBE RHEL-07-040490
  describe package('lftpd') do
    it { should_not be_installed }
  end

  describe port(21) do
    it { should_not be_listening }
  end
# STOP_DESCRIBE RHEL-07-040490

end

