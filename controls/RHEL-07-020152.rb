# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020152 - The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of packages without verification of the repository metadata.'
control 'RHEL-07-020152' do
  impact 1.0
  title 'The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of packages without verification of the repository metadata.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.  Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.  Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved Certificate Authority.'
  tag 'stig', 'RHEL-07-020152'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020152_chk'
  tag fixid: 'F-RHEL-07-020152_fix'
  tag version: 'RHEL-07-020152'
  tag ruleid: 'RHEL-07-020152_rule'
  tag fixtext: 'Configure the operating system to verify the repository metadata by setting the following options in the /etc/yum.conf file:

repo_gpgcheck=1'
  tag checktext: 'Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification of the repository metadata.

Check that yum verifies the package metadata prior to install with the following command:

# grep repo_gpgcheck /etc/yum.conf
repo_gpgcheck=1

If "repo_gpgcheck" is not set to ”1”, or if options are missing or commented out, this is a finding.'

# START_DESCRIBE RHEL-07-020152
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-020152

end

