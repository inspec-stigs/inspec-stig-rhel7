# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-020170 - Operating systems handling data requiring data-at-rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.'
control 'RHEL-07-020170' do
  impact 1.0
  title 'Operating systems handling data requiring data-at-rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.'
  desc 'Selection of a cryptographic mechanism is based on the need to protect the integrity and confidentiality of sensitive information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). This requirement is applicable if the organization determines that its sensitive information is to be protected at the storage device level.  Satisfies: SRG-OS-000405-GPOS-00184, SRG-OS-000185-GPOS-00079'
  tag 'stig', 'RHEL-07-020170'
  tag severity: 'high'
  tag checkid: 'C-RHEL-07-020170_chk'
  tag fixid: 'F-RHEL-07-020170_fix'
  tag version: 'RHEL-07-020170'
  tag ruleid: 'RHEL-07-020170_rule'
  tag fixtext: 'Configure the operating system to implement cryptographic mechanisms to prevent unauthorized disclosure of all sensitive information at rest on operating system storage devices. This must be performed during the creation of the operating system as attempting to encrypt the system partitions afterward is not a trivial operation.'
  tag checktext: 'Verify the operating system, if handling data that requires protection to prevent the unauthorized discloser or modification of information at rest, is using disk encryption. 

Note: If the organization determines that no data resident on the system requires protection, or that sensitive data is being protected through an application encryption mechanism, this requirement is Not Applicable.

Check the system partitions to determine if they are all encrypted with the following command:

# blkid
/dev/sda1: UUID=" ab12c3de-4f56-789a-8f33-3850cc8ce3a2
" TYPE="crypto_LUKS"
/dev/sda2: UUID=" bc98d7ef-6g54-321h-1d24-9870de2ge1a2
" TYPE="crypto_LUKS"

Pseudo-file systems, such as /proc, /sys, and tmpfs, are not required to use disk encryption and are not a finding. 

If any other partitions do not have a type of “crypto_LUKS”, this is a finding.'

# START_DESCRIBE RHEL-07-020170
  blkids = command('blkid').stdout.split("\n")
  blkids.each do |blkid|
    describe command("echo '#{blkid}'") do
      its('stdout') { should match /^.+TYPE="crypto_LUKS".*$/ }
    end
  end
# STOP_DESCRIBE RHEL-07-020170

end

