#!/bin/env python

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.racktables_py_client.client import RacktablesClient


ANSIBLE_METADATA = {
    'metadata_version': '0.1',
    'status': ['preview'],
    'supported_by': 'nesanton@gmail.com'
}

DOCUMENTATION = '''
---
module: racktables

short_description: This is my sample module

version_added: "0.1"

description:
    - This module can to add and edit entries in https://www.racktables.org/
      It makes use of a php api extention to racktables
      https://github.com/nesanton/racktables/blob/master/wwwroot/api.php
      Currently only one object type is supported - server (obj_type_id=4).

options:
    api:
        description:
            - api string to connect to racktables php api
        required: False
        default: https://racktables/api.php
    user:
        description:
            - user to connect to racktables php api
        required: True
    password:
        description:
            - password to be used with I(user)
        required: True
    action:
        description:
            - what to do. Most useful is C(update). It will edit all the specified attributes, but won't touch the rest.
              Module will perform search trying to match exactly one object using I(search_by).
              If no objects are found - a new one will be added. If many - module will fail.
        choices: [search, add, update]
        required: True
    search_by:
        description:
            - Which field to use for search.
        choices: [name, asset_no]
        default: asset_no
        required: False
    name:
        description:
            - name of racktables object. Required only if used by I(search_by)
        required: False
    object_type:
        description:
            - type of racktables object. Only C(server) is supported at the moment.
        choices: [server, ]
        default: server
        required: False
    asset_no:
        description:
            - asset_no of racktables object. Required only if used by I(search_by) (default)
        required: False
    label:
        description:
            - label of racktables object.
        required: False
    comment:
        description:
            - comment of racktables object.
        required: False
    preserve_comment:
        description:
            - If C(yes), then new comment will be appended to existing comment after two  newlines.
              C(yes) cannot be idempotent.
        type: bool
        default: no
        required: False
    tags:
        description:
            - List of tags to link with the object. If any of the provided tags don't exist, they will be created.
        required: False
    preserve_tags:
        description:
            - If C(yes), keeps all the assigned tags and just adds what's missing in I(tags).
        type: bool
        default: no
        required: False
    ports:
        description:
            - Dictionary of <interface_name>: <mac_address> pairs. Object's ports. Only name and mac can be provided.
        required: False
    preserve_ports:
        description:
            - If C(yes), keeps all existing ports even if they are not provided in I(ports).
        type: bool
        default: no
        required: False
    ips:
        description:
            - Dictionary of <ip_address>: <interface_name> pairs. Object's ip addresses.
              Only interface name and ip address can be provided.
              Interface name does not have to exist or be provided in I(ports).
        required: False
    preserve_ips:
        description:
            - If C(yes), keeps all existing ips even if they are not provided in I(ports).
        type: bool
        default: no
        required: False
    attrs:
        description:
            - Dictionary of <attr_name>: <attr_value> pairs. Object's extended attributes (yellow on view tab).
              <attr_name> has to exactly match such of racktables attribute. If <attr_value> is a dictionary value
              and the provided value does not exist in the dictionary - it will be added.
        required: False

author:
    - Anton Nesterov (@nesanton)
'''

EXAMPLES = '''
# A comprehensive example
- name: Update racktables object
  racktables:
    api: http://racktables/api.php
    user: username
    password: password  # can use vault
    action: update
    name: "{{ ansible_nodename }}"
    asset_no: "{{ ansible_product_uuid }}"
    ports:
      eth0: ""
      whatever0: "FF:00:EE:00:DD:00"
    ips:
      192.168.1.2: eth0
      192.168.2.2: eth0
      192.168.3.2: whatever0
      192.168.4.2: eth6
    preserve_ips: yes
    tags:
      - newtag
      - anothertag
    preserve_tags: yes
    attrs:
      SW type: "{{ ansible_distribution }}%GPASS%{{ ansible_distribution_version }}"
      HW type: "SuperMicro%GPASS%server model"
      Hypervisor: "No"
      contact person: "John Doe"
      FQDN: "{{ ansible_fqdn }}"
'''

RETURN = '''
full_object_spec:
  description: full json object spec as it's returned by RacktablesClient.get_object
  type: dict
  returned: success
message:
  description: a short result string
  returned: success
  choices: [added, updated, failed]
updates:
  description: structure with all the updates made to an object
  type: dict
  returned: success
  sample: {
    "attrs": {
      "FQDN": {
        "new": "server1.example.org",
        "old": "server1.example.com" },
      "SW type": {
        "new": "CentOS%GPASS%7.4.1708",
        "old": "Linux" }},
    "ips": {
      "added": {
        "192.0.2.2": "eth0" },
      "deleted": {},
      "preserved": [
        "192.168.5.2" ],
      "updated": {
        "192.0.2.3": "eth1" }}
  }
'''


def resolve_tags(taglist, rt_client):
    """
    Makes sure all needed tags are present before assignment.
    :param taglist: list of tags requested in the playbook
    :param rt_client: instance of RacktablesClient
    :return (tags_created, errors): list of created tags and list of tags we failed to create
    """
    tags_created = []
    errors = []
    raw_tags = rt_client.get_tags()
    # make a more useful dict: {"tag1": 100, "tag2": 201}
    all_tags = {v['tag']: int(k) for k, v in raw_tags.iteritems()}
    for tag in taglist:
        if tag not in all_tags:
            # add new tag
            tag_id = rt_client.add_tag(tag)
            if tag_id:
                tags_created.append(tag)
            else:
                errors.append(tag)
    return tags_created, errors


def resolve_attrs(text_attrs, objtype_id, rt_client):
    """
    Translates text attrs into cahpter ids when needed
    :param text_attrs: dict of attrs, e.g. {"HW type": "some type", "FQDN": "name.example.com", "attr1": "val1"}
    :param objtype_id: id of object_type, e.g. server == 4
    :param rt_client: instance of RacktablesClient
    :return (result, errors): where result is the translated text_attrs, e.g. {"2": "50120", "3": "name.example.com"}
    and errors is a dict of error messages per attr {"attr1": "could not resolve attribute"}
    """
    result = {}
    errors = {}
    attrs = rt_client.get_attributes()
    for key, value in text_attrs.iteritems():
        attr_id = None
        chapter_no = None
        dictionary = False

        for attr in attrs:
            if attrs[attr].get('name', None) == key:
                attr_id = attr
                if attrs[attr].get('type', None) == 'dict':
                    dictionary = True
                if dictionary:
                    for app in attrs[attr]['application'].values():
                        if app['objtype_id'] == str(objtype_id):
                            chapter_no = app.get('chapter_no', None)
                            break
        if dictionary:
            if chapter_no:
                entry_id = rt_client.get_chapter_entry_id(chapter_no, value)

                if not entry_id:
                    entry_id = rt_client.add_chapter_entry(chapter_no, value)

                result[attr_id] = entry_id
            else:
                errors[key] = 'Could not resolve attribute'
        else:
            if attr_id:
                result[attr_id] = value
            else:
                errors[key] = 'Could not resolve attribute'
    return result, errors


def process_ports(object_ports, playbook_ports):
    """
    Process port list from the playbook to see what to add, update and delete.

    We are not going to mangle port types and other parameters besides name and mac address.
    It is not worth the effort to try and tell what speed and link type a port has and then try
    to resolve these parameters in racktables' dictionaries and port type mappings. User can manually
    change any port parameters including label without affecting module idempotency.
    Hence the comparison is done only between mac and name.
    :params object_ports: dict, current full port definition from get_object's 'ports' key
    :params playbook_ports: dict, {portname: macaddress} collected from the playbook's 'ports' parameter
    :return port_updates: dict, {portname: 'intact|update|delete|add'}
    """
    # do nothing if playbook portlist is empty
    if not playbook_ports:
        return {}

    # make a nicer dict of object_ports
    # the 'k' below is rubbish - it's an id of port to object relationship
    oports = {v['name']: v for k, v in object_ports.iteritems()}
    # dict for comparison - ensures that lowercase and uppercase port names can match
    pports = {k.lower(): v.lower() for k, v in playbook_ports.iteritems()}
    port_updates = {}
    for port in oports:
        if port.lower() in pports:
            # name match
            if oports[port]['l2address']:
                # name match, mac populated
                if oports[port]['l2address'].lower() == pports[port.lower()]:
                    # name match, mac match
                    port_updates[port] = 'intact'
                else:
                    # name match, no mac match
                    port_updates[port] = 'update'
            elif pports[port.lower()]:
                # name match, mac not populated, but provided in playbook
                port_updates[port] = 'update'
            else:
                # name match, mac not populated, and not provided in playbook
                port_updates[port] = 'intact'
        else:
            # no name match => delete
            port_updates[port] = 'delete'
    # Now let's see what's left to add
    port_updates_lowercase = [k.lower() for k in port_updates]
    for port in playbook_ports:
        if port.lower() not in port_updates_lowercase:
            # we have not seen this port among existing object interfaces, so that's new
            port_updates[port] = 'add'
    return port_updates


def process_ips(object_ips, playbook_ips):
    """
    Scan thru provided IP addresses to see what to add/delete/update.

    :param object_ips: dict, current full ip definition from get_object's 'ipv4' key
    :param playbook_ips: dict {interface: ip_address,} provided in playbook
    :return ip_updates: dict {ip: 'intact|update|delete|add'}
    """
    if not playbook_ips:
        return {}
    ip_updates = {}
    oips = {v['addrinfo']['ip']: v['osif'] for v in object_ips.values()}
    for ip in oips:
        if ip in playbook_ips:
            # this ip is provided in the playbook
            if oips[ip].lower() == playbook_ips[ip].lower():
                # interface name is the same
                ip_updates[ip] = 'intact'
            else:
                # interface name is different
                ip_updates[ip] = 'update'
        else:
            # ip is not provided in the playbook
            ip_updates[ip] = 'delete'
    for ip in playbook_ips:
        if ip not in ip_updates:
            # we have not seen this ip yet => add
            ip_updates[ip] = 'add'
    return ip_updates


def dict_empty(d):
    empty = True
    for k, v in d.iteritems():
        if isinstance(v, dict):
            empty = dict_empty(d[k])
        else:
            if v:
                empty = False
    return empty


def dict_to_log_string(val, indent=1):
    indent += 1
    tab = ''
    for i in range(0, indent):
        tab += '  '
    s = ''
    if isinstance(val, dict):
        leaf = True
        for value in val.values():
            if isinstance(value, dict) or isinstance(value, list):
                leaf = False
        if leaf:
            s += ' '
            s += ', '.join(['='.join(['{i}'.format(i=i) for i in x]) for x in val.items()])
        else:
            for k, v in val.iteritems():
                if v:
                    s += '\n{tab}{k}: '.format(tab=tab, k=k)
                    s += dict_to_log_string(v, indent)
    elif isinstance(val, list):
        if val:
            s = ', '.join(val)
    else:
        if val:
            s = str(val)
    return s


def add_object(module, params, rt_client):
    """
    Adds an object to racktables.
    :param module: ansible module instance (needed for error handlers and original attr values)
    :param params: reworked module.params['attrs'] to better suit api needs
    :param rt_client: instance of RacktablesClient
    :return result: dict with module results
    """
    result = dict(changed=True,
                  updates=dict(attrs=dict(),
                               ignored_attrs=dict(),
                               attr_errors=dict(),
                               tags=dict(added=list(), dropped=list(), created=list(), preserved=list())))

    tags_created, tag_errors = resolve_tags(params['taglist'], rt_client)
    if tag_errors:
        module.fail_json(msg='Could not create tags: {tags}. Check php_fpm logs'.format(tags=' '.join(tag_errors)),
                         **result)
    if tags_created:
            result['updates']['tags']['created'] = tags_created

    params['attrs'], errors = resolve_attrs(params['attrs'], params['object_type_id'], rt_client)
    if errors:
        for key, value in errors.iteritems():
            module.warn('{key}: {value}'.format(key=key, value=value))
            # attr_errors contains error message per attr
            # ignored_attrs - attr values
            result['updates']['attr_errors'][key] = value
            result['updates']['ignored_attrs'][key] = module.params['attrs'][key]
    obj = rt_client.add_object(**params)
    if not obj:
        module.fail_json(msg='Could not add object. Already exists? Check php_fpm logs', **result)
    for port, mac in module.params['ports'].iteritems():
        new_port_id = rt_client.add_object_port(obj['id'], port, mac)
        if not new_port_id:
            module.fail_json(msg='Could not add port {port} to object. Check php_fpm logs'.format(port=port),
                             **result)

    for ip in module.params['ips']:
        if not rt_client.add_object_ipv4_address(obj['id'], ip, module.params['ips'][ip]):
            module.fail_json(msg='Failed to allocate ip {ip}. Check php_fpm logs'.format(ip=ip), **result)

    result['message'] = 'added'

    log = ''
    for key in sorted(result['updates']):
        if not dict_empty(result['updates'][key]):
            log += '{key}:'.format(key=key)
            log += dict_to_log_string(result['updates'][key])
            log += '\n'
    rt_client.add_object_log(obj['id'], log)
    result['full_object_spec'] = rt_client.get_object(obj['id'], True, True)
    return result


def update_object(module, params, rt_client):
    """
    Updates an object in racktables.
    :param module: ansible module instance (needed for error handlers and original attr values)
    :param params: reworked module.params['attrs'] to better suit api needs
    :param rt_client: instance of RacktablesClient
    :return result: dict with module results
    """
    obj_id = None
    result = dict(changed=False,
                  updates=dict(ports=dict(added=dict(), updated=dict(), deleted=dict(), preserved=list()),
                               ips=dict(added=dict(), updated=dict(), deleted=dict(), preserved=list()),
                               attrs=dict(),
                               ignored_attrs=dict(),
                               attr_errors=dict(),
                               tags=dict(added=list(), dropped=list(), created=list(), preserved=list())))
    search_response = rt_client.search(module.params[module.params['search_by']])
    if 'response' in search_response:
        if 'object' in search_response['response']:
            ids = search_response['response']['object'].keys()
            if len(ids) > 1:
                module.fail_json(msg='too many objects found', **result)
            elif len(ids) == 0:
                return add_object(module, params, rt_client)
            else:
                obj_id = ids[0]
        else:
            return add_object(module, params, rt_client)
    else:
        return add_object(module, params, rt_client)
    obj = rt_client.get_object(obj_id, True, True)

    # Check if any of the standard object parameters are being changed
    for key in ['name', 'asset_no', 'label', 'comment']:
        if params.get('object_{key}'.format(key=key), None) is not None and \
                        obj[key] != params['object_{key}'.format(key=key)]:
            result['changed'] = True
            result['updates'][key] = {'old': obj[key], 'new': params['object_{key}'.format(key=key)]}
    # Check if any extended object parameters (yellow in racktables) are being changed
    new_attrs = params['attrs']
    old_attrs = obj['attrs']
    if new_attrs:
        for key, value in new_attrs.iteritems():
            if key in old_attrs:
                if value != old_attrs[key]['value']:
                    result['changed'] = True
                    result['updates']['attrs'][key] = {'old': old_attrs[key]['value'], 'new': value}
            else:
                result['updates']['ignored_attrs'][key] = value
                # object does not have such attribute, so
                # it will be ignored by php code in "edit_object"

    # Translate extended attributes into chapter values when needed
    resolved_attrs, errors = resolve_attrs(new_attrs, obj['objtype_id'], rt_client)
    if errors:
        for key, value in errors.iteritems():
            module.warn('{key}: {value}'.format(key=key, value=value))
            result['updates']['attr_errors'][key] = value
            if key not in result['updates']['ignored_attrs']:
                result['updates']['ignored_attrs'][key] = module.params['attrs'][key]

    # Create new tags if needed
    taglist = params['taglist']
    tags_created, tag_errors = resolve_tags(taglist, rt_client)
    if tag_errors:
        module.fail_json(msg='Could not create tags: {tags}. Check php_fpm logs'.format(tags=' '.join(tag_errors)),
                         **result)
    if tags_created:
            result['updates']['tags']['created'] = tags_created
            result['changed'] = True

    # Check if tags are being changed
    current_tags = [tagdata['tag'] for tagdata in obj['etags'].values()]

    if module.params['preserve_tags']:
        for tag in current_tags:
            if tag not in taglist:
                taglist.append(tag)
                result['updates']['tags']['preserved'].append(tag)
    else:
        tags_dropped = [tag for tag in current_tags if tag not in taglist]
        if tags_dropped:
                result['updates']['tags']['dropped'] = tags_dropped
                result['changed'] = True
    for tag in taglist:
        if tag not in current_tags:
            result['changed'] = True
            result['updates']['tags']['added'].append(tag)

    safe_params = {'object_name': params.get('object_name', obj['name']),
                   'object_asset_no': params.get('object_asset_no', obj['asset_no']),
                   'object_label': params.get('object_label', obj['label']),
                   'object_comment': params.get('object_comment', ''),
                   'append_comment': module.params['preserve_comment'],
                   'attrs': resolved_attrs}
    rt_client.edit_object_safe(obj_id, **safe_params)
    if taglist:
        rt_client.update_object_tags(obj_id, taglist)

    # handle ports
    port_updates = process_ports(obj['ports'], module.params['ports'])
    ports_to_add = [p for p in port_updates if port_updates[p] == 'add']
    ports_to_delete = [p for p in port_updates if port_updates[p] == 'delete']
    ports_to_update = [p for p in port_updates if port_updates[p] == 'update']
    oports = {v['name']: v for k, v in obj['ports'].iteritems()}
    for port in ports_to_add:
        # returns object id
        if rt_client.add_object_port(obj_id, port, module.params['ports'][port]):
            result['updates']['ports']['added'][port] = dict(mac=module.params['ports'][port])
            result['changed'] = True
        else:
            module.fail_json(msg='Could not add port {port} to object. Check php_fpm logs'.format(port=port),
                             **result)
    for port in ports_to_update:
        # returns true if successful
        if rt_client.update_object_port(obj_id,
                                        oports[port]['id'],
                                        port,
                                        oports[port]['label'],
                                        module.params['ports'][port],
                                        oports[port]['reservation_comment'],
                                        port_type_id='{iif}-{oif}'.format(iif=oports[port]['iif_id'],
                                                                          oif=oports[port]['oif_id'])):
            result['updates']['ports']['updated'][port] = dict(mac=dict(old=oports[port]['l2address'],
                                                                        new=module.params['ports'][port]))
            result['changed'] = True
        else:
            module.fail_json(msg='Could not update object port: {port}. Check php_fpm logs'.format(port=port),
                             **result)
    for port in ports_to_delete:
        if module.params['preserve_ports']:
            # instead of deleting we'll update label to "OBSOLETED <date>"
            result['updates']['ports']['preserved'].append(port)
        else:
            # returns true if successful
            if rt_client.delete_object_port(obj_id, oports[port]['id']):
                result['updates']['ports']['deleted'][port] = dict(mac=oports[port]['l2address'],
                                                                   label=oports[port]['label'])
                result['changed'] = True
            else:
                module.fail_json(msg='Failed to delete port {port}. Check php_fpm logs'.format(port=port),
                                 **result)

    ip_updates = process_ips(obj['ipv4'], module.params['ips'])
    ips_to_add = {k: v for k, v in ip_updates.iteritems() if v == 'add'}
    ips_to_update = {k: v for k, v in ip_updates.iteritems() if v == 'update'}
    ips_to_delete = {k: v for k, v in ip_updates.iteritems() if v == 'delete'}
    oips = {v['addrinfo']['ip']: v['osif'] for v in obj['ipv4'].values()}

    for ip in ips_to_add:
        if rt_client.add_object_ipv4_address(obj['id'], ip, module.params['ips'][ip]):
            result['updates']['ips']['added'][ip] = module.params['ips'][ip]
            result['changed'] = True
        else:
            module.fail_json(msg='Failed to allocate ip {ip}. Check php_fpm logs'.format(ip=ip),
                             **result)
    for ip in ips_to_update:
        if rt_client.edit_object_ipv4_address(obj['id'], ip, module.params['ips'][ip]):
            result['updates']['ips']['updated'][ip] = dict(old=oips[ip], new=module.params['ips'][ip])
            result['changed'] = True
        else:
            module.fail_json(msg='Failed to update records for ip {ip}. Check php_fpm logs'.format(ip=ip),
                             **result)
    for ip in ips_to_delete:
        if module.params['preserve_ips']:
            result['updates']['ips']['preserved'].append(ip)
        else:
            if rt_client.delete_object_ipv4_address(obj['id'], ip):
                result['updates']['ips']['deleted'][ip] = oips[ip]
                result['changed'] = True
            else:
                module.fail_json(msg='Failed to delete ip {ip}. Check php_fpm logs'.format(ip=ip),
                                 **result)

    if result['changed']:
        result['message'] = 'updated'
        log = ''
        for key in sorted(result['updates']):
            if not dict_empty(result['updates'][key]):
                log += '{key}:'.format(key=key)
                log += dict_to_log_string(result['updates'][key])
                log += '\n'
        rt_client.add_object_log(obj['id'], log)
    else:
        result['message'] = 'not updated'
    result['full_object_spec'] = rt_client.get_object(obj_id, True, True)
    return result


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    search_choices = ['name',
                      'asset_no',
                      'label',
                      'comment']
    obj_type_choices = ['server']
    obj_type_id = {'server': 4}

    module_args = dict(
        api=dict(type='str', required=False, default='https://racktables/api.php'),
        user=dict(type='str', required=True),
        password=dict(type='str', required=True),
        action=dict(type='str', required=True),
        search_by=dict(type='str', required=False, choices=search_choices),
        name=dict(type='str', required=False),
        object_type=dict(type='str', required=False, choices=obj_type_choices, default='server'),
        asset_no=dict(type='str', required=False),
        label=dict(type='str', required=False),
        comment=dict(type='str', required=False),
        preserve_comment=dict(type='bool', required=False, default=False),
        tags=dict(type='list', required=False),
        preserve_tags=dict(type='bool', required=False, default=False),
        ports=dict(type='dict', required=False),
        preserve_ports=dict(type='bool', required=False, default=False),
        ips=dict(type='dict', required=False),
        preserve_ips=dict(type='bool', required=False, default=False),
        attrs=dict(type='dict')
    )

    # seed the result dict in the object
    result = dict(
        changed=False,
        updates=dict()
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    # make a connection to racktables
    rt_client = RacktablesClient(module.params['api'],
                                 username=module.params['user'],
                                 password=module.params['password'])

    # Handle parameter dependencies and restrictions
    if module.params['search_by'] is None:
        # decide how to handle search based on given args
        module.params['search_by'] = 'asset_no'

    # mutually exclusive - object_type and update => all that is immutable on update
    # comment - never idempotent

    object_definition = {'object_name': module.params['name'],
                         'object_asset_no': module.params['asset_no'],
                         'object_label': module.params['label'],
                         'object_comment': module.params['comment'],
                         'object_type_id': obj_type_id[module.params['object_type']],
                         'taglist': module.params['tags'],
                         'attrs': module.params['attrs']}

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        return result

    if module.params['action'] == 'search':
        search_response = rt_client.search(module.params[module.params['search_by']])
        if 'response' in search_response:
            if 'object' in search_response['response']:
                result['search_results'] = search_response['response']['object']
            else:
                result['search_results'] = {}
    elif module.params['action'] == 'update':
        result.update(update_object(module, object_definition, rt_client))
    elif module.params['action'] == 'add':
        result.update(add_object(module, object_definition, rt_client))

    module.exit_json(**result)


def main():
    run_module()

if __name__ == '__main__':
    main()
