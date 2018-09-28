# racktables_ansible
ansible module for racktables

## installation

Uncomment library string in /etc/ansible/ansible.cfg, so ansible can find our modules there
```
library = /usr/share/ansible
```

Clone the repo into some deployment folder  and ake links into custom modules folder
```
ln -s $PWD/racktables_ansible/racktables* /usr/share/ansible/
```

Clone the racktables_py_client repo into some deployment folder and make links to module_utils
(custom module_utils did not want to work for me, so I'm using the standard /usr/lib/...)
```
ln -s $PWD/racktable_py_client /usr/lib/python2.7/site-packages/ansible/module_utils/
```

## racktables_facts

It turned out that writing a playbook for racktables module and taking args from ansible_facts is a tricky task. ansible_facts are very poorly structured. You'll end up either iterating a lot with loops over interfaces and ip addresses or preparing facts with set_facts. In both cases the playbook will be hardly readable due to many filters and complex with_together loops. E.g. iterating over ipv4_secondaries is a disaster. 

racktables_facts is a sample module written in bash that collects facts for racktables module. It arranges the facts in a json that is directly mappable to module_args of racktables module. Why bash? In case any custom platform-specific or software-dependant facts are needed for, say, a custom racktables attribute, one can easyly extend this bash script to run any util available in linux with no need for extra python libs.

Being a sample, it won't fit your environment straight away as many things are hardcoded. E.g. virtualization is only KVM and OS is only CentOS.
