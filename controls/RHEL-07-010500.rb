# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010500 - The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multi-factor authentication.'
control 'RHEL-07-010500' do
  impact 0.5
  title 'The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multi-factor authentication.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.  Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:  1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication;   and  2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.  Satisfies: SRG-OS-000104-GPOS-00051, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000109-GPOS-00056, SRG-OS-000108-GPOS-00055, SRG-OS-000108-GPOS-00057, SRG-OS-000108-GPOS-00058'
  tag 'stig', 'RHEL-07-010500'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010500_chk'
  tag fixid: 'F-RHEL-07-010500_fix'
  tag version: 'RHEL-07-010500'
  tag ruleid: 'RHEL-07-010500_rule'
  tag fixtext: 'Configure the operating system to require individuals to be authenticated with a multi-factor authenticator.

Enable smartcard logins with the following commands:

# authconfig --enablesmartcard --smartcardaction=1 --update
# authconfig --enablerequiresmartcard -update

Modify the /etc/pam_pkcs11/pkcs11_eventmgr.conf file to uncomment the following line:

#/usr/X11R6/bin/xscreensaver-command -lock

Modify the /etc/pam_pkcs11/pam_pkcs11.conf file to use the cackey module if required.'
  tag checktext: 'Verify the operating system requires multifactor authentication to uniquely identify organizational users using multi-factor authentication.

Check to see if smartcard authentication is enforced on the system:

# authconfig --test | grep -i smartcard

The entry for use only smartcard for login may be enabled, and the smartcard module and smartcard removal actions must not be blank.

If smartcard authentication is disabled or the smartcard and smartcard removal actions are blank, this is a finding.'

# START_DESCRIBE RHEL-07-010500
  describe command('authconfig --test') do
    its('stdout') { should match /^smartcard module = ".+"/ }
    its('stdout') { should match /^smartcard removal action = ".+"/ }
  end
# STOP_DESCRIBE RHEL-07-010500

end

