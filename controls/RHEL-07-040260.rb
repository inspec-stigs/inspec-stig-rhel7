# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040260 - All networked systems must have SSH installed.'
control 'RHEL-07-040260' do
  impact 0.5
  title 'All networked systems must have SSH installed.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.   This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.   Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.  Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000423-GPOS-00188, SRG-OS-000423-GPOS-00189, SRG-OS-000423-GPOS-00190'
  tag 'stig', 'RHEL-07-040260'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040260_chk'
  tag fixid: 'F-RHEL-07-040260_fix'
  tag version: 'RHEL-07-040260'
  tag ruleid: 'RHEL-07-040260_rule'
  tag fixtext: 'Install SSH packages onto the host with the following commands:

# yum install openssh-clients.x86_64
# yum install openssh-server.x86_64

Note: 32-bit versions will require different packages.'
  tag checktext: 'Check to see if sshd is installed with the following command:

# yum list installed | grep ssh
libssh2.x86_64                           1.4.3-8.el7               @anaconda/7.1
openssh.x86_64                           6.6.1p1-11.el7            @anaconda/7.1
openssh-clients.x86_64                   6.6.1p1-11.el7            @anaconda/7.1
openssh-server.x86_64                    6.6.1p1-11.el7            @anaconda/7.1

If the “SSH server” package is not installed, this is a finding.

If the “SSH client” package is not installed, this is a finding.'

# START_DESCRIBE RHEL-07-040260
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040260

end

