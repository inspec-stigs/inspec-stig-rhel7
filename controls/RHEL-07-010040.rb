# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
banner_message_text = attribute('banner_message_text', default: '^You are accessing', description: 'text to match for banner message')

title 'RHEL-07-010040 - The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.'
control 'RHEL-07-010040' do
  impact 0.5
  title 'The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.  The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:  "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.  By using this IS (which includes any device attached to this IS), you consent to the following conditions:  -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.  -At any time, the USG may inspect and seize data stored on this IS.  -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.  -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.  -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."  Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:  "I\'ve read  consent to terms in IS user agreem\'t."  Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007'
  tag 'stig', 'RHEL-07-010040'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010040_chk'
  tag fixid: 'F-RHEL-07-010040_fix'
  tag version: 'RHEL-07-010040'
  tag ruleid: 'RHEL-07-010040_rule'
  tag fixtext: 'Configure the operating system to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via the command line by editing the /etc/issue file.

Replace the default text with the Standard Mandatory DoD Notice and Consent Banner. The DoD required text is:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  tag checktext: 'Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon.

Check to see if the operating system displays a banner at the command line logon screen with the following command:

# more /etc/issue

The command should return the following text:
“You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.”

If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

If the text in the /etc/issue file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.'

# START_DESCRIBE RHEL-07-010040
  describe file('/etc/issue') do
    its('content') { should match /#{banner_message_text}/ }
  end
# STOP_DESCRIBE RHEL-07-010040

end

