# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030331 - The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.'
control 'RHEL-07-030331' do
  impact 0.5
  title 'The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.  Off-loading is a common process in information systems with limited audit storage capacity.  Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224'
  tag 'stig', 'RHEL-07-030331'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030331_chk'
  tag fixid: 'F-RHEL-07-030331_fix'
  tag version: 'RHEL-07-030331'
  tag ruleid: 'RHEL-07-030331_rule'
  tag fixtext: 'Configure the operating system to encrypt the transfer of off-loaded audit records onto a different system or media from the system being audited.

Uncomment the enable_krb5 option in /etc/audisp/audisp-remote.conf and set it with the following line:

enable_krb5 = yes'
  tag checktext: 'Verify the operating system encrypts audit records off-loaded onto a different system or media from the system being audited.

To determine if the transfer is encrypted, use the following command:

# grep -i enable_krb5 /etc/audisp/audisp-remote.conf
enable_krb5 = yes

If the value of the “enable_krb5” option is not set to "yes" or the line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-030331
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-030331

end

