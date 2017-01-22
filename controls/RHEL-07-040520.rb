# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040520 - If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode.'
control 'RHEL-07-040520' do
  impact 0.5
  title 'If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.'
  tag 'stig', 'RHEL-07-040520'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040520_chk'
  tag fixid: 'F-RHEL-07-040520_fix'
  tag version: 'RHEL-07-040520'
  tag ruleid: 'RHEL-07-040520_rule'
  tag fixtext: 'Configure the TFTP daemon to operate in secure mode by adding the following line to /etc/xinetd.d/tftp (or modify the line to have the required value):

server_args = -s /var/lib/tftpboot'
  tag checktext: 'Verify the TFTP daemon is configured to operate in secure mode.

Check to see if a TFTP server has been installed with the following commands:

# yum list installed | grep tftp
tftp-0.49-9.el7.x86_64.rpm

If a TFTP server is not installed, this is Not Applicable.

If a TFTP server is installed, check for the server arguments with the following command: 

# grep server_arge /etc/xinetd.d/tftp
server_args = -s /var/lib/tftpboot

If the “server_args” line does not have a -s option and the directory /var/lib/tftpboot, this is a finding.'

# START_DESCRIBE RHEL-07-040520
  is_tftp_installed = package('tftp').installed?
  if is_tftp_installed
    describe file('/etc/xinetd.d/tftp') do
      its('content') { should match /^server_args\s*=.*-s.*$/ }
      its('content') { should match /^server_args\s*=.*\/var\/lib\/tftpboot.*$/ }
    end
  end
# STOP_DESCRIBE RHEL-07-040520

end

