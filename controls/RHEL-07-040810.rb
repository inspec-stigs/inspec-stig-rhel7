# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040810 - The system must use a local firewall.'
control 'RHEL-07-040810' do
  impact 0.5
  title 'The system must use a local firewall.'
  desc 'A firewall provides the ability to enhance system security posture by restricting services to known good IP addresses and address ranges. This prevents connections from unknown hosts and protocols.'
  tag 'stig', 'RHEL-07-040810'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040810_chk'
  tag fixid: 'F-RHEL-07-040810_fix'
  tag version: 'RHEL-07-040810'
  tag ruleid: 'RHEL-07-040810_rule'
  tag fixtext: 'Install “firewalld” on the system if it is not already installed with the following command:

# yum install firewalld firewall-config

Enable firewalld with the following command:

#systemctl enable firewalld'
  tag checktext: 'Verify that a firewall is in use on the system.

Check to see if “firewalld” is installed with the following command:

# yum list installed | grep firewalld

If “firewalld” is not installed, ask the System Administrator if they are performing another method of access control (such as iptables) for all network services on the system. 

If there is no access control being performed on all network services, this is a finding.

If “firewalld” is installed, determine whether it is active with the following command:

# systemctl status firewalld
firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago

If “firewalld” is not active, this is a finding.'

# START_DESCRIBE RHEL-07-040810
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040810

end

