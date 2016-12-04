# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020250 - System security patches and updates must be installed and up to date.'
control 'RHEL-07-020250' do
  impact 0.5
  title 'System security patches and updates must be installed and up to date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced system administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  tag 'stig', 'RHEL-07-020250'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-020250_chk'
  tag fixid: 'F-RHEL-07-020250_fix'
  tag version: 'RHEL-07-020250'
  tag ruleid: 'RHEL-07-020250_rule'
  tag fixtext: 'Install the operating system patches or updated packages available from Red Hat within 30 days or sooner as local policy dictates.'
  tag checktext: 'Verify the operating system security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO). 

Obtain the list of available package security updates from Red Hat. The URL for updates is https://rhn.redhat.com/errata/. It is important to note that updates provided by Red Hat may not be present on the system if the underlying packages are not installed.

Check that the available package security updates have been installed on the system with the following command:

# yum history list | more
Loaded plugins: langpacks, product-id, subscription-manager
ID     | Command line             | Date and time    | Action(s)      | Altered
-------------------------------------------------------------------------------
    70 | install aide             | 2016-05-05 10:58 | Install        |    1   
    69 | update -y                | 2016-05-04 14:34 | Update         |   18 EE
    68 | install vlc              | 2016-04-21 17:12 | Install        |   21   
    67 | update -y                | 2016-04-21 17:04 | Update         |    7 EE
    66 | update -y                | 2016-04-15 16:47 | E, I, U        |   84 EE

If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding. 

Typical update frequency may be overridden by information assurance vulnerability alert (IAVA) notifications from CYBERCOM.

If the operating system is in non-compliance with the IAVM process, this is a finding.'

# START_DESCRIBE RHEL-07-020250
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020250

end

