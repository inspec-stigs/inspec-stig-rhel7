# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020940 - All system device files must be correctly labeled to prevent unauthorized modification.'
control 'RHEL-07-020940' do
  impact 0.5
  title 'All system device files must be correctly labeled to prevent unauthorized modification.'
  desc 'If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations.'
  tag 'stig', 'RHEL-07-020940'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020940_chk'
  tag fixid: 'F-RHEL-07-020940_fix'
  tag version: 'RHEL-07-020940'
  tag ruleid: 'RHEL-07-020940_rule'
  tag fixtext: 'Run the following command to determine which package owns the device file:

# rpm -qf <filename>

The package can be reinstalled from a yum repository using the command:

# sudo yum reinstall <packagename>

Alternatively, the package can be reinstalled from trusted media using the command:

# sudo rpm -Uvh <packagename>'
  tag checktext: 'Verify that all system device files are correctly labeled to prevent unauthorized modification.

List all device files on the system that are incorrectly labeled with the following commands:

Note: Device files are normally found under “/dev”, but applications may place device files in other directories, necessitating a search of the entire system.

#find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"

#find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"

If there is output from either of these commands, this is a finding.'

# START_DESCRIBE RHEL-07-020940
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020940

end

