# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020220 - The x86 Ctrl-Alt-Delete key sequence must be disabled.'
control 'RHEL-07-020220' do
  impact 1.0
  title 'The x86 Ctrl-Alt-Delete key sequence must be disabled.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  tag 'stig', 'RHEL-07-020220'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020220_chk'
  tag fixid: 'F-RHEL-07-020220_fix'
  tag version: 'RHEL-07-020220'
  tag ruleid: 'RHEL-07-020220_rule'
  tag fixtext: 'Configure the system to disable the Ctrl-Alt_Delete sequence for the command line with the following command:

# systemctl mask ctrl-alt-del.target

If Gnome is active on the system, create a database to contain the system-wide setting (if it does not already exist) with the following command: 

# cat /etc/dconf/db/local.d/00-disable-CAD 

Add the setting to disable the Ctrl-Alt_Delete sequence for Gnome:

[org/gnome/settings-daemon/plugins/media-keys]
logout=’’'
  tag checktext: 'Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.service is not active with the following command:

# systemctl status ctrl-alt-del.service
reboot.target - Reboot
   Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)
   Active: inactive (dead)
     Docs: man:systemd.special(7)

If the ctrl-alt-del.service is active , this is a finding.'

# START_DESCRIBE RHEL-07-020220
  describe service('ctrl-alt-del') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# STOP_DESCRIBE RHEL-07-020220

end

