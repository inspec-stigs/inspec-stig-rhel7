# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020200 - The operating system must remove all software components after updated versions have been installed.'
control 'RHEL-07-020200' do
  impact 0.1
  title 'The operating system must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  tag 'stig', 'RHEL-07-020200'
  tag severity: 'low'
  tag checkid: 'C-RHEL-07-020200_chk'
  tag fixid: 'F-RHEL-07-020200_fix'
  tag version: 'RHEL-07-020200'
  tag ruleid: 'RHEL-07-020200_rule'
  tag fixtext: 'Configure the operating system to remove all software components after updated versions have been installed.

Set the “clean_requirements_on_remove” option to “1” in the /etc/yum.conf file:

clean_requirements_on_remove=1'
  tag checktext: 'Verify the operating system removes all software components after updated versions have been installed.

Check if yum is configured to remove unneeded packages with the following command:

# grep -i clean_requirements_on_remove /etc/yum.conf
clean_requirements_on_remove=1

If “clean_requirements_on_remove” is not set to “1”, “True”, or “yes”, or is not set in /etc/yum.conf, this is a finding.'

# START_DESCRIBE RHEL-07-020200
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020200

end

