# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010420 - The delay between logon prompts following a failed console logon attempt must be at least four seconds.'
control 'RHEL-07-010420' do
  impact 0.5
  title 'The delay between logon prompts following a failed console logon attempt must be at least four seconds.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.  Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  tag 'stig', 'RHEL-07-010420'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010420_chk'
  tag fixid: 'F-RHEL-07-010420_fix'
  tag version: 'RHEL-07-010420'
  tag ruleid: 'RHEL-07-010420_rule'
  tag fixtext: 'Configure the operating system to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.

Modify the “/etc/login.defs” file to set the “FAIL_DELAY” parameter to “4” or greater:

FAIL_DELAY 4'
  tag checktext: 'Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt.

Check the value of the fail_delay parameter in “/etc/login.defs” file with the following command:

# grep -i fail_delay /etc/login.defs
FAIL_DELAY 4

If the value of “FAIL_DELAY” is not set to “4” or greater, this is a finding.'

# START_DESCRIBE RHEL-07-010420
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-010420

end

