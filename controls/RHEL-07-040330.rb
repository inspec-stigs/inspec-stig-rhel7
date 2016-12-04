# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040330 - There must be no .shosts files on the system.'
control 'RHEL-07-040330' do
  impact 1.0
  title 'There must be no .shosts files on the system.'
  desc 'The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  tag 'stig', 'RHEL-07-040330'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-040330_chk'
  tag fixid: 'F-RHEL-07-040330_fix'
  tag version: 'RHEL-07-040330'
  tag ruleid: 'RHEL-07-040330_rule'
  tag fixtext: 'Remove any found .shosts files from the system.

# rm /[path]/[to]/[file]/.shosts'
  tag checktext: 'Verify there are no .shosts files on the system.

Check the system for the existence of these files with the following command:

# find / -name \'*.shosts’

If any .shosts files are found on the system, this is a finding.'

# START_DESCRIBE RHEL-07-040330
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040330

end

