# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020090 - The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
control 'RHEL-07-020090' do
  impact 0.5
  title 'The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.  Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  tag 'stig', 'RHEL-07-020090'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020090_chk'
  tag fixid: 'F-RHEL-07-020090_fix'
  tag version: 'RHEL-07-020090'
  tag ruleid: 'RHEL-07-020090_rule'
  tag fixtext: 'Configure the operating system to prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Use the following command to map a new user to the sysdam_u role: 

#semanage login -a -s sysadm_u <username>

Use the following command to map an existing user to the sysdam_u role:

#semanage login -m -s sysadm_u <username>

Use the following command to map a new user to the staff_u role:

#semanage login -a -s staff_u <username>

Use the following command to map an existing user to the staff_u role:

#semanage login -m -s staff_u <username>

Use the following command to map a new user to the user_u role:

# semanage login -a -s user_u <username>

Use the following command to map an existing user to the user_u role:

# semanage login -m -s user_u <username>'
  tag checktext: 'Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Get a list of authorized users (other than system administrator and guest accounts) for the system.

Check the list against the system by using the following command:

# semanage login -l | more
Login Name  SELinux User   MLS/MCS Range  Service
__default__  user_u    s0-s0:c0.c1023   *
root   unconfined_u   s0-s0:c0.c1023   *
system_u  system_u   s0-s0:c0.c1023   *
joe  staff_u   s0-s0:c0.c1023   *

All administrators must be mapped to the sysadm_u or staff_u users with the appropriate domains (sysadm_t and staff_t).

All authorized non-administrative users must be mapped to the user_u role or the appropriate domain (user_t).

If they are not mapped in this way, this is a finding.'

# START_DESCRIBE RHEL-07-020090
#  TODO: Complete this finding
#  describe file('') do
#    it { should match // }
#  end
# STOP_DESCRIBE RHEL-07-020090

end

