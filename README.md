# inspec-stig-rhel7

Inspec for RHEL7 STIG.

## Note about the auditd rules

The official STIGs auditd rules are not in the correct syntax or outdated in a few ways. Below is the list of the issues found and how to correct them.

1. Rules with the ``key`` field missing the ``-F`` parameter breaking the rule syntax
    * Prepended the invalid ``key`` rules with ``-F`` 
2. Rules where the field ``subj`` is defined is an invalid field name, valid the correct field names are ``subj_user``, ``subj_role``, ``subj_typ``, ``subj_sen``, ``subj_clr``
    *  Lines where ``-F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023`` is defined needed to be changed to ``-F subj_user=unconfined_u -F subj_role=unconfined_r -F subj_type=unconfined_t -F subj_sen=s0-s0 -F subj_clr=c0.c1023``. Basically split it out to the correct syntax
3. Rules where the field and value ``-F auid!=4294967295`` is can be set to the proper value of ``-F auid!=-1``
    *  Setting the value to ``4294967295`` was a hack because of an issue in the kernel as described [here](http://lkml.iu.edu/hypermail/linux/kernel/1304.1/01594.html). The setting can now be safely set as ``-1``

## Getting Started

Assuming you have Vagrant installed you can use the following to
get a machine capable of running the STIGs.

```
$ git clone https://github.com/inspec-stigs/inspec-stig-rhel7.git
$ cd inspec-stig-rhel7
$ vagrant up

```
