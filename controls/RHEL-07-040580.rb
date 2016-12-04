# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040580 - SNMP community strings must be changed from the default.'
control 'RHEL-07-040580' do
  impact 1.0
  title 'SNMP community strings must be changed from the default.'
  desc 'Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings.'
  tag 'stig', 'RHEL-07-040580'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-040580_chk'
  tag fixid: 'F-RHEL-07-040580_fix'
  tag version: 'RHEL-07-040580'
  tag ruleid: 'RHEL-07-040580_rule'
  tag fixtext: 'If the “/etc/snmp/snmpd.conf” file exists, modify any lines that contain a community string of public or private to another string.'
  tag checktext: 'Verify that a system using SNMP is not using default community strings.

Check to see if the “/etc/snmp/snmpd.conf” file exists with the following command:

# ls -al /etc/snmp/snmpd.conf
 -rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf

If the file does not exist, this is Not Applicable.

If the file does exist, check for the default community strings with the following commands:

# grep public /etc/snmp/snmpd.conf
# grep private /etc/snmp/snmpd.conf

If either of these command returns any output, this is a finding.'

# START_DESCRIBE RHEL-07-040580
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040580

end

