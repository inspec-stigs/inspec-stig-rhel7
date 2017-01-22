# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020000 - The rsh-server package must not be installed.'
control 'RHEL-07-020000' do
  impact 1.0
  title 'The rsh-server package must not be installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.  Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.  If a privileged user were to log on using this service, the privileged user password could be compromised.'
  tag 'stig', 'RHEL-07-020000'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020000_chk'
  tag fixid: 'F-RHEL-07-020000_fix'
  tag version: 'RHEL-07-020000'
  tag ruleid: 'RHEL-07-020000_rule'
  tag fixtext: 'Configure the operating system to disable non-essential capabilities by removing the rsh-server package from the system with the following command:

# yum remove rsh-server'
  tag checktext: 'Check to see if the rsh-server package is installed with the following command:

# yum list installed | grep rsh-server

If the rsh-server package is installed, this is a finding.'

# START_DESCRIBE RHEL-07-020000
  describe package('rsh-server') do
    it { should_not be_installed }
  end
# STOP_DESCRIBE RHEL-07-020000

end

