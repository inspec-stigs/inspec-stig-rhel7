# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020211 - The operating system must enable the SELinux targeted policy.'
control 'RHEL-07-020211' do
  impact 1.0
  title 'The operating system must enable the SELinux targeted policy.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.  This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  tag 'stig', 'RHEL-07-020211'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020211_chk'
  tag fixid: 'F-RHEL-07-020211_fix'
  tag version: 'RHEL-07-020211'
  tag ruleid: 'RHEL-07-020211_rule'
  tag fixtext: 'Configure the operating system to verify correct operation of all security functions.

Set the “Selinuxtype” to the “targeted” policy by modifying the /etc/selinux/config file to have the following line:

SELINUXTYPE=targeted

A reboot is required for the changes to take effect.'
  tag checktext: 'Verify the operating system verifies correct operation of all security functions.

Check if SELinux is active and is enforcing the targeted policy with the following command:

# sestatus
SELinux status:                 enabled
SELinuxfs mount:                /selinux
Current mode:                   enforcing
Mode from config file:          enforcing
Policy version:                 24
Policy from config file:        targeted

If the “Policy from config file”  not set to “targeted”, this is a finding.'

# START_DESCRIBE RHEL-07-020211
  describe command('sestatus') do
    its('stdout') { should match /^SELinux status:\s+enabled$/ }
    its('stdout') { should match /^Current mode:\s+enforcing$/ }
    its('stdout') { should match /^Mode from config file:\s+enforcing$/ }
    its('stdout') { should match /^Policy from config file:\s+targeted$/ }
  end
# STOP_DESCRIBE RHEL-07-020211

end

