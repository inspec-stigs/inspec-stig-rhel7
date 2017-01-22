# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-030090 - The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.'
control 'RHEL-07-030090' do
  impact 0.5
  title 'The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.  Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.  This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.  Satisfies: SRG-OS-000046-GPOS-00022, SRG-OS-000047-GPOS-00023'
  tag 'stig', 'RHEL-07-030090'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-030090_chk'
  tag fixid: 'F-RHEL-07-030090_fix'
  tag version: 'RHEL-07-030090'
  tag ruleid: 'RHEL-07-030090_rule'
  tag fixtext: 'Configure the operating system to shut down in the event of an audit processing failure.

Add or correct the following line in the /etc/audit/auditd.confs file:

auditctl -f 2

If availability has been determined to be more important, and this decision is documented with the ISSO, configure the operating system to notify system administration staff and ISSO staff in the event of audit processing failure.

Add or correct the following line in the /etc/audit/auditd.conf file:

auditctl -f 1

Kernel log monitoring must also be configured to properly alert designed staff.

The audit daemon must be restarted for the changes to take effect.'
  tag checktext: 'Confirm the audit configuration regarding how auditing processing failures are handled.

Check to see what level auditctl is set to in /etc/audit/auditd.conf with the following command: 

# grep \-f /etc/audit/auditd.conf
auditctl -f 2

If the value of "-f" is set to “2”, the system is configured to panic (shut down) in the event of an auditing failure.

If the value of "-f" is set to “1”, the system is configured to only send information to the kernel log regarding the failure.

If the "-f" flag is not set, this is a CAT I finding.

If the "-f" flag is set to any value other than “1” or “2”, this is a CAT II finding.

If the "-f" flag is set to “1” but the availability concern is not documented or there is no monitoring of the kernel log, this is a CAT III finding.'

# START_DESCRIBE RHEL-07-030090
  describe command('grep -rE "\-f\s+2" /etc/audit/*') do
    its('exit_status') { should eq 0 }
  end
# STOP_DESCRIBE RHEL-07-030090

end

