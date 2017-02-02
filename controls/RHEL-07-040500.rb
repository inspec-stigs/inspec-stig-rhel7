# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040500 - The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support.'
control 'RHEL-07-040500' do
  impact 1.0
  title 'The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support.'
  desc 'If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Manager (ISSM), restricted to only authorized personnel, and have access control rules established.'
  tag 'stig', 'RHEL-07-040500'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-040500_chk'
  tag fixid: 'F-RHEL-07-040500_fix'
  tag version: 'RHEL-07-040500'
  tag ruleid: 'RHEL-07-040500_rule'
  tag fixtext: 'Remove the TFTP package from the system with the following command:

# yum remove tftp'
  tag checktext: 'Verify a TFTP server has not been installed on the system.

Check to see if a TFTP server has been installed with the following command:

# yum list installed | grep tftp-server
tftp-server-0.49-9.el7.x86_64.rpm

An alternate method of determining if a TFTP server is active on the server is to use the following commands:

# netstat -a | grep 69
# netstat -a | grep 8099

If TFTP is installed and the requirement for TFTP is not documented with the ISSM, this is a finding.'

# START_DESCRIBE RHEL-07-040500
  describe package('tftp') do
    it { should_not be_installed }
  end

  describe port('69') do
    it { should_not be_listening }
  end

  describe port('8099') do
    it { should_not be_listening }
  end
# STOP_DESCRIBE RHEL-07-040500

end

