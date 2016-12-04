# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-040680 - The SSH daemon must perform strict mode checking of home directory configuration files.'
control 'RHEL-07-040680' do
  impact 0.5
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  tag 'stig', 'RHEL-07-040680'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-040680_chk'
  tag fixid: 'F-RHEL-07-040680_fix'
  tag version: 'RHEL-07-040680'
  tag ruleid: 'RHEL-07-040680_rule'
  tag fixtext: 'Uncomment the “StrictModes” keyword in /etc/ssh/sshd_config (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "yes":

StrictModes yes'
  tag checktext: 'Verify the SSH daemon performs strict mode checking of home directory configuration files.

The location of the sshd_config file may vary on the system and can be found using the following command:

# find / -name \'sshd*_config\' 

If there is more than one ssh server daemon configuration file on the system, determine which daemons are active on the system with the following command:

# ps -ef | grep sshd

The command will return the full path of the ssh daemon. This will indicate which sshd_config file will be checked with the following command:

# grep -i strictmodes /etc/ssh/sshd_config
StrictModes yes

If “StrictModes” is set to "no", is missing, or the retuned line is commented out, this is a finding.'

# START_DESCRIBE RHEL-07-040680
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-040680

end

