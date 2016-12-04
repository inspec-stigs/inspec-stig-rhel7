# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020630 - All local interactive user accounts, upon creation, must be assigned a home directory.'
control 'RHEL-07-020630' do
  impact 0.5
  title 'All local interactive user accounts, upon creation, must be assigned a home directory.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  tag 'stig', 'RHEL-07-020630'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020630_chk'
  tag fixid: 'F-RHEL-07-020630_fix'
  tag version: 'RHEL-07-020630'
  tag ruleid: 'RHEL-07-020630_rule'
  tag fixtext: 'Configure the operating system to assign home directories to all new local interactive users by setting the “CREATE_HOME” parameter in “/etc/login.defs” to “yes” as follows.

CREATE_HOME yes'
  tag checktext: 'Verify all local interactive users on the system are assigned a home directory upon creation.

Check to see if the system is configured to create home directories for local interactive users with the following command:

# grep -i create_home /etc/login.defs
CREATE_HOME yes

If the value for “CREATE_HOME” parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-020630
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020630

end

