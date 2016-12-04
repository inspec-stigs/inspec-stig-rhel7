# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040560 - An X Windows display manager must not be installed unless approved.'
control 'RHEL-07-040560' do
  impact 0.5
  title 'An X Windows display manager must not be installed unless approved.'
  desc 'Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented.'
  tag 'stig', 'RHEL-07-040560'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040560_chk'
  tag fixid: 'F-RHEL-07-040560_fix'
  tag version: 'RHEL-07-040560'
  tag ruleid: 'RHEL-07-040560_rule'
  tag fixtext: 'Document the requirement for an X Windows server with the ISSM or remove the related packages with the following commands:

#yum groupremove "X Window System"

#yum remove xorg-x11-server-common'
  tag checktext: 'Verify that if the system has X Windows installed, it is authorized.

Check for the X11 package with the following command:

#yum groupinstall "X Window System"

Ask the System Administrator (SA) if use of the X Windows system is an operational requirement.

If the use of X Windows on the system is not documented with the Information System Security Manager (ISSM), this is a finding.'

# START_DESCRIBE RHEL-07-040560
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040560

end

