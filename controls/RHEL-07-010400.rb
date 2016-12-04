# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010400 - The operating system must prohibit the use of cached nss authenticators after one day.'
control 'RHEL-07-010400' do
  impact 0.5
  title 'The operating system must prohibit the use of cached nss authenticators after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  tag 'stig', 'RHEL-07-010400'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010400_chk'
  tag fixid: 'F-RHEL-07-010400_fix'
  tag version: 'RHEL-07-010400'
  tag ruleid: 'RHEL-07-010400_rule'
  tag fixtext: 'Configure the operating system to prohibit the use of cached nss authenticators after one day.

If “nss” is in use on the system, set the “memcache_timeout” value to “86400” or less in /etc/sssd/sssd.conf:

memcache_timeout = 86400'
  tag checktext: 'Verify the operating system prohibits the use of cached nss authenticators after one day.

Check to see if the “sssd” service is active with the following command:

# systemctl status sssd.service

If the service is active, the command will return:

sssd.service - System Security Services Daemon
   Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled)
   Active: active (running) since Thu 2014-09-25 10:46:43 CEST; 5s ago

If the service is not active, this is a finding.

Check the services option for the active services of each domain configured with the following command:

# grep services /etc/sssd/sssd.conf

The command will return one line for each domain. In the example:

services = nss, pam
services = nss, pam

There are two services lines as the “nss” and “pam” services are being used by two domains (ldap and local).

If nss is an active service, check the memcache_timeout option with the following command:

# grep -i memcache_timeout /etc/sssd/sssd.conf
memcache_timeout = 86400

If the “memcache_timeout” is set to a value greater than “86400”, is commented out, or is missing, this is a finding.'

# START_DESCRIBE RHEL-07-010400
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-010400

end

