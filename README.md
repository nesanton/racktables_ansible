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
