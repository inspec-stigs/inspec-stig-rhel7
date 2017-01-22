# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020210 - The operating system must enable SELinux.'
control 'RHEL-07-020210' do
  impact 1.0
  title 'The operating system must enable SELinux.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.  This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  tag 'stig', 'RHEL-07-020210'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020210_chk'
  tag fixid: 'F-RHEL-07-020210_fix'
  tag version: 'RHEL-07-020210'
  tag ruleid: 'RHEL-07-020210_rule'
  tag fixtext: 'Configure the operating system to verify correct operation of all security functions.

Set the “Selinux” status and the “enforcing” mode by modifying the /etc/selinux/config file to have the following line:

SELINUX=enforcing

A reboot is required for the changes to take effect.'
  tag checktext: 'Verify the operating system verifies correct operation of all security functions.

Check if SELinux is active and in enforcing mode with the following command:

# getenforce
Enforcing

If the “SELinux” mode is not set to “Enforcing”, this is a finding.'

# START_DESCRIBE RHEL-07-020210
  describe command('getenforce') do
    its('stdout') { should eq 'Enforcing' }
  end
# STOP_DESCRIBE RHEL-07-020210

end

