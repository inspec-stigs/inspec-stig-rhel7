# inspec-stig-rhel7

Inspec for RHEL7 STIG.

## Note about the auditd rules

The official STIGs auditd rules are not in the correct syntax or outdated in a few ways. Below is the list of the issues found and how to correct them.

1. Rules with the ``key`` field missing the ``-F`` parameter breaking the rule syntax
    * **Fix**: Prepend the invalid ``key`` rules with ``-F`` 
2. Rules where the field ``subj`` is defined is an invalid field name, the correct ``subj`` field names are ``subj_user``, ``subj_role``, ``subj_typ``, ``subj_sen``, ``subj_clr``
    * **Fix**: Lines where ``-F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023`` is defined needed to be changed to ``-F subj_user=unconfined_u -F subj_role=unconfined_r -F subj_type=unconfined_t -F subj_sen=s0-s0 -F subj_clr=c0.c1023``. Splitting it out to the correct syntax
3. Rules with the field and value ``-F auid!=4294967295`` can be set to the proper value of ``-F auid!=-1``
    * **Fix**: Setting the value to ``4294967295`` was a workaround due to an issue in the kernel as described [here](http://lkml.iu.edu/hypermail/linux/kernel/1304.1/01594.html). The setting can be safely set as ``-1`` now

## Getting Started

Assuming you have Vagrant installed you can use the following to
get a machine capable of running the STIGs.

```
$ git clone https://github.com/inspec-stigs/inspec-stig-rhel7.git
$ cd inspec-stig-rhel7
$ vagrant up

```
