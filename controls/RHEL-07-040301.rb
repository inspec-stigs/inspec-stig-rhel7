# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040301 - The system must display the date and time of the last successful account logon upon an SSH logon.'
control 'RHEL-07-040301' do
  impact 0.5
  title 'The system must display the date and time of the last successful account logon upon an SSH logon.'
  desc 'Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.'
  tag 'stig', 'RHEL-07-040301'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040301_chk'
  tag fixid: 'F-RHEL-07-040301_fix'
  tag version: 'RHEL-07-040301'
  tag ruleid: 'RHEL-07-040301_rule'
  tag fixtext: 'Configure SSH to provide users with feedback on when account accesses last occurred by setting the required configuration options in “/etc/pam.d/sshd” or in the “sshd_config” file used by the system (/etc/ssh/sshd_config will be used in the example) (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

Add the following line to the top of “/etc/pam.d/sshd”:

session     required      pam_lastlog.so showfailed

Or modify the PrintLastLog line in “/etc/ssh/sshd_config” to match the following:

PrintLastLog yes'
  tag checktext: 'Verify SSH provides users with feedback on when account accesses last occurred.

Check that “PrintLastLog” keyword in the sshd daemon configuration file is used and set to “yes” with the following command:

# grep -i printlastlog /etc/ssh/sshd_config
PrintLastLog yes

If the “PrintLastLog” keyword is set to “no”, is missing, or is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040301
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040301

end

