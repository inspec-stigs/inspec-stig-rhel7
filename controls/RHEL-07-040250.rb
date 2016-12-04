# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040250 - The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces.'
control 'RHEL-07-040250' do
  impact 0.5
  title 'The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  tag 'stig', 'RHEL-07-040250'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040250_chk'
  tag fixid: 'F-RHEL-07-040250_fix'
  tag version: 'RHEL-07-040250'
  tag ruleid: 'RHEL-07-040250_rule'
  tag fixtext: 'Create a direct firewall rule to protect against DoS attacks with the following command:

# firewall-cmd --direct --add-rule ipv4 filter IN_public_allow 0 -m tcp -p tcp -m limit --limit 25/minute --limit-burst 100  -j ACCEPT'
  tag checktext: 'Verify the operating system protects against or limits the effects of DoS attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.

Check the firewall configuration with the following command:

# firewall-cmd --direct --get-rule ipv4 filter IN_public_allow
rule ipv4 filter IN_public_allow 0 -m tcp -p tcp -m limit --limit 25/minute --limit-burst 100  -j ACCEPT

If a rule with both the limit and limit-burst arguments parameters does not exist, this is a finding.'

# START_DESCRIBE RHEL-07-040250
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040250

end

