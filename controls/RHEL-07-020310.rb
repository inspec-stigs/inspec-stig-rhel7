# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020310 - The root account must be the only account having unrestricted access to the system.'
control 'RHEL-07-020310' do
  impact 1.0
  title 'The root account must be the only account having unrestricted access to the system.'
  desc 'If an account other than root also has a User Identifier (UID) of “0”, it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of “0” afford an opportunity for potential intruders to guess a password for a privileged account.'
  tag 'stig', 'RHEL-07-020310'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020310_chk'
  tag fixid: 'F-RHEL-07-020310_fix'
  tag version: 'RHEL-07-020310'
  tag ruleid: 'RHEL-07-020310_rule'
  tag fixtext: 'Change the UID of any account on the system, other than root, that has a UID of “0”. 

If the account is associated with system commands or applications, the UID should be changed to one greater than “0” but less than “1000”. Otherwise, assign a UID of greater than “1000” that has not already been assigned.'
  tag checktext: 'Check the system for duplicate UID “0” assignments with the following command:

# awk -F: \'$3 == 0 {print $1}\' /etc/passwd

If any accounts other than root have a UID of “0”, this is a finding.'

# START_DESCRIBE RHEL-07-020310
  describe passwd.uids(0) do
    its('users') { should cmp 'root' }
    its('entries.length') { should eq 1 }
  end
# STOP_DESCRIBE RHEL-07-020310

end

