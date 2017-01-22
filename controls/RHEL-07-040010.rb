# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040010 - The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
control 'RHEL-07-040010' do
  impact 0.1
  title 'The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.  This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.'
  tag 'stig', 'RHEL-07-040010'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-040010_chk'
  tag fixid: 'F-RHEL-07-040010_fix'
  tag version: 'RHEL-07-040010'
  tag ruleid: 'RHEL-07-040010_rule'
  tag fixtext: 'Configure the operating system to limit the number of concurrent sessions to 10 for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf:

* hard maxlogins 10'
  tag checktext: 'Verify the operating system limits the number of concurrent sessions to ten for all accounts and/or account types by issuing the following command:

# grep "maxlogins" /etc/security/limits.conf
* hard maxlogins 10

This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

If the maxlogins item is missing or the value is not set to 10 or less for all domains that have the maxlogins item assigned, this is a finding.'

# START_DESCRIBE RHEL-07-040010
  describe file('/etc/security/limits.conf') do
    its('content') { should match /^.+\s+hard\s+maxlogins\s+[0-9]+/ }
  end

  maxlogins = command('grep -iE "^.+\s+hard\s+maxlogins\s+[0-9]+" /etc/security/limits.conf | grep -Eo "[0-9]+"').stdout.split("\n")
  for maxlogin in maxlogins do
    describe command("if [ #{maxlogin} -le 10 ]; then exit 0; else exit 1; fi") do
      its('exit_status') { should eq 0 }
    end
  end
# STOP_DESCRIBE RHEL-07-040010

end

