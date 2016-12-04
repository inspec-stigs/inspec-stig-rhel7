# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020010 - The ypserv package must not be installed.'
control 'RHEL-07-020010' do
  impact 1.0
  title 'The ypserv package must not be installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  tag 'stig', 'RHEL-07-020010'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020010_chk'
  tag fixid: 'F-RHEL-07-020010_fix'
  tag version: 'RHEL-07-020010'
  tag ruleid: 'RHEL-07-020010_rule'
  tag fixtext: 'Configure the operating system to disable non-essential capabilities by removing the “ypserv” package from the system with the following command:

# yum remove ypserv'
  tag checktext: 'The NIS service provides an unencrypted authentication service that does not provide for the confidentiality and integrity of user passwords or the remote session.

Check to see if the “ypserve” package is installed with the following command:

# yum list installed | grep ypserv

If the “ypserv” package is installed, this is a finding.'

# START_DESCRIBE RHEL-07-020010
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020010

end

