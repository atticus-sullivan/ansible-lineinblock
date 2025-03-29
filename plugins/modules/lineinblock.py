#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = r'''
---
module: lineinblock
short_description: Append or remove a line within a delimited block in a file
description:
  - This module ensures a particular line is present or absent within a delimited block in a file.
  - If the line was absent, it always gets appended to the block!
  - This is primarily useful for configuration files with structured blocks (like unattended-upgrade configs).
  - See the M(ansible.builtin.lineinfile) module if you want to modify a single line in a file.
  - See the M(ansible.builtin.blockinfile) module if you want to insert/update/remove a block of lines.
options:
  path:
    description:
      - The file to modify.
    type: path
    required: true
    aliases: [ dest, name ]
  line:
    description:
      - The line to insert/remove within the delimited block.
      - Required for C(state=present).
    type: str
    required: true
    aliases: [ value ]
  start_delimiter:
    description:
      - The string that marks the beginning of the block.
      - Default is set for unattended-upgrade configuration.
      - Required
    type: str
  end_delimiter:
    description:
      - The string that marks the end of the block.
      - Default is set for unattended-upgrade configuration.
      - Required.
    type: str
  state:
    description:
      - Whether the line should be present or absent in the block.
    type: str
    choices: [ present, absent ]
    default: present
  create:
    description:
      - Create the file if it does not exist.
      - When set to C(false), the module will fail if the file does not exist.
    type: bool
    default: false
  backup:
    description:
      - Create a backup file including the timestamp information.
    type: bool
    default: false
extends_documentation_fragment:
  - action_common_attributes
  - action_common_attributes.files
  - files
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: posix
notes:
  - This module works with delimited blocks where braces are used to define block boundaries.
  - The brace-counting logic may not handle complex cases with braces in comments or strings.
seealso:
  - module: ansible.builtin.lineinfile
  - module: ansible.builtin.blockinfile
author:
  - Lukas Heindl (@atticus-sullivan)
'''

EXAMPLES = r'''
# Ensure a particular package origin is in the unattended-upgrade config
- name: Add security updates to unattended-upgrades
  lineinblock:
    path: /etc/apt/apt.conf.d/50unattended-upgrades
    line: '    "${distro_id}:${distro_codename}-security";'
    start_delimiter: 'Unattended-Upgrade::Origins-Pattern {'
    end_delimiter: '};'
    state: present

# Remove a package origin from unattended-upgrade config
- name: Remove proposed updates from unattended-upgrades
  lineinblock:
    path: /etc/apt/apt.conf.d/50unattended-upgrades
    line: '    "${distro_id}:${distro_codename}-proposed";'
    state: absent

# Create a new config file with a predefined block structure
- name: Create new unattended-upgrade config with security updates
  lineinblock:
    path: /etc/apt/apt.conf.d/51my-unattended-upgrades
    line: '    "${distro_id}:${distro_codename}-security";'
    create: yes
'''

RETURN = r'''
backup_file:
  description: Name of the backup file that was created.
  returned: when backup=yes and changed=yes
  type: str
  sample: /path/to/file.txt.2023-03-29@12:13:15~
msg:
  description: Status message.
  returned: always
  type: str
  sample: Line inserted successfully
changed:
  description: Whether the file was modified.
  returned: always
  type: bool
  sample: true
diff:
  description: Unified diff of before and after the change.
  returned: when diff=yes
  type: dict
  contains:
    before:
      description: Content of the file before modification.
      returned: success
      type: str
    after:
      description: Content of the file after modification.
      returned: success
      type: str
'''

import os
import tempfile

# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text

def process_config_file(file_path, line_to_insert, start_delimiter, end_delimiter, state='present'):
    """
    Process a configuration file to insert or remove a line within a delimited block.

    Args:
        file_path (str): Path to the configuration file
        line_to_insert (str): Line to insert or remove
        start_delimiter (str): String that marks the beginning of the block
        end_delimiter (str): String that marks the end of the block
        state (str): Either 'present' to ensure line exists or 'absent' to remove it

    Returns:
        tuple: (changed, lines, contains_line) indicating if file was changed,
               the new file content, and whether the line was already present
    """

    with open(file_path, 'r') as file:
        lines = file.readlines()
    lines_stripped = [line.strip() for line in lines]

    # Initialize variables
    in_block = False
    block_start_index = None
    block_end_index = None
    brace_count = 0
    changed = False
    contains_line = False

    # Identify block using the provided delimiters
    for i, line in enumerate(lines_stripped):
        if not in_block and line == start_delimiter:
            in_block = True
            # TODO needs to be variable?
            brace_count = start_delimiter.count('{') # Count the opening brace
            block_start_index = i
            continue

        if in_block:
            # Count nested braces to find the matching end
            # TODO doesn't account for braces inside comments, strings, or escaped characters
            open_braces = line.count('{') # TODO needs to be variable?
            close_braces = line.count('}') # TODO needs to be variable?
            brace_count += open_braces - close_braces

            if brace_count == 0 and line == end_delimiter:
                block_end_index = i
                break

    # Exit if no block was found
    if block_start_index is None or block_end_index is None:
        return changed, lines, contains_line

    # If block is found, process it according to state
    # Extract block content to check if line already exists
    block_lines = lines_stripped[block_start_index+1:block_end_index]
    contains_line = line_to_insert.strip() in block_lines

    # Detect line ending from file
    line_ending = '\n'
    if lines and lines[0].endswith('\r\n'):
        line_ending = '\r\n'

    if state == 'present' and not contains_line:
        # Insert line just before the end delimiter
        lines.insert(block_end_index, line_to_insert + line_ending)
        changed = True
    elif state == 'absent' and contains_line:
        # Find and remove the line
        idx = lines_stripped.index(line_to_insert.strip())
        lines.pop(idx)
        changed = True

    return changed, lines, contains_line

def write_changes(module, lines, dest):
    """
    Write changes to the destination file using temp file and atomic move.

    Args:
        module: The AnsibleModule object
        lines: List of lines to write to the file
        dest: Destination file path
    """

    tmpfd, tmpfile = tempfile.mkstemp(dir=module.tmpdir)

    with os.fdopen(tmpfd, 'wb') as f:
        f.writelines([line.encode('utf-8') if isinstance(line, str) else line for line in lines])

    # TODO validate parameter
    # validate = module.params.get('validate', None)
    # valid = not validate
    # if validate:
    #     if "%s" not in validate:
    #         module.fail_json(msg="validate must contain %%s: %s" % (validate))
    #     (rc, out, err) = module.run_command(to_bytes(validate % tmpfile, errors='surrogate_or_strict'))
    #     valid = rc == 0
    #     if rc != 0:
    #         module.fail_json(msg='failed to validate: '
    #                              'rc:%s error:%s' % (rc, err))
    # if valid:
    #     module.atomic_move(tmpfile,
    #                        to_native(os.path.realpath(to_bytes(dest, errors='surrogate_or_strict')), errors='surrogate_or_strict'),
    #                        unsafe_writes=module.params['unsafe_writes'])

    module.atomic_move(tmpfile, to_native(os.path.realpath(to_bytes(dest, errors='surrogate_or_strict')), errors='surrogate_or_strict'), unsafe_writes=module.params['unsafe_writes'])

def check_file_attrs(module, changed, message, diff):
    """
    Check and update file attributes if needed.

    Args:
        module: The AnsibleModule object
        changed: Boolean indicating if content has changed
        message: Current status message
        diff: Diff dictionary to update

    Returns:
        tuple: (message, changed) with updated status
    """

    file_args = module.load_file_common_arguments(module.params)
    if module.set_fs_attributes_if_different(file_args, False, diff=diff):
        if changed:
            message += " and "
        changed = True
        message += "ownership, perms or SE linux context changed"

    return message, changed

def main():
    module_args = dict(
        path=dict(type='path', required=True, aliases=["dest", "name"]),
        line=dict(type='str', required=True, aliases=["value"]),
        start_delimiter=dict(type='str', required=True),
        end_delimiter=dict(type='str', required=True),
        backup=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        create=dict(type='bool', default=False),
        # Add common file arguments
        unsafe_writes=dict(type='bool', default=False),
    )

    result = dict(
        changed=False,
        message='',
        backup_file=None,
        diff=dict(
            before='',
            after=''
        )
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        add_file_common_args=True
    )

    params = module.params
    path = params['path']
    line_to_insert = params['line']
    start_delimiter = params['start_delimiter']
    end_delimiter = params['end_delimiter']
    backup = params['backup']
    state = params['state']
    create = params['create']

    # Validate path to protect against directory traversal
    b_path = to_bytes(path, errors='surrogate_or_strict')
    if os.path.isdir(b_path):
        module.fail_json(rc=256, msg=f'Path {path} is a directory!')

    # Extract the normalized absolute path
    try:
        path = os.path.normpath(os.path.realpath(os.path.expanduser(path)))
    except Exception as e:
        module.fail_json(msg=f"Path normalization failed: {to_native(e)}")

    # Check if file exists
    if not os.path.exists(path):
        if not create:
            module.fail_json(rc=257, msg=f'File does not exist: {path}, use create=yes to create it')
        if not module.check_mode:
            # Create parent directories if needed
            parent_dir = os.path.dirname(path)
            if parent_dir and not os.path.exists(parent_dir):
                try:
                    os.makedirs(parent_dir)
                except Exception as e:
                    module.fail_json(msg=f'Error creating directory {parent_dir}: {to_native(e)}')
            # Create empty file
            try:
                with open(path, 'w') as f:
                    # Add the structure with delimiters and the line
                    if state == 'present':
                        f.write(f"{start_delimiter}\n{line_to_insert}\n{end_delimiter}\n")
                    elif state == 'absent':
                        f.write(f"{start_delimiter}\n{end_delimiter}\n")
            except IOError as e:
                module.fail_json(msg=f'Error creating file {path}: {to_native(e)}')

            result['changed'] = True
            result['message'] = f'File created with block {"and line " if state=="present" else ""}inserted'

            # Set file attributes if specified
            file_args = module.load_file_common_arguments(module.params)
            module.set_fs_attributes_if_different(file_args, True)

            module.exit_json(**result)
        else:
            result['changed'] = True
            result['message'] = f'File would be created with block {"and line " if state=="present" else ""}inserted (check mode)'
            module.exit_json(**result)

    # Read file content for diff
    if module._diff:
        with open(path, 'r') as f:
            result['diff']['before'] = f.read()

    # Process the file
    changed, new_lines, contains_line = process_config_file(
        path, 
        line_to_insert, 
        start_delimiter, 
        end_delimiter,
        state
    )

    # Update diff if needed
    if module._diff and changed:
        result['diff']['after'] = ''.join(new_lines)

    # Make backup if requested and the file will be changed
    if backup and changed and not module.check_mode:
        result['backup_file'] = module.backup_local(path)

    # Write changes if needed
    if changed and not module.check_mode:
        write_changes(module, new_lines, path)

        # Set file attributes if specified
        attr_diff = {}
        message = ''
        if state == 'present':
            message = 'Line inserted successfully'
        else:
            message = 'Line removed successfully'

        result['message'], changed = check_file_attrs(module, changed, message, attr_diff)

    elif not changed:
        if state == 'present' and contains_line:
            result['message'] = 'Line already exists in the block, no changes needed'
        elif state == 'absent' and not contains_line:
            result['message'] = 'Line not found in the block, no changes needed'
        else:
            result['message'] = 'No matching block found, no changes made'
    else:
        # Changed but check mode
        if state == 'present':
            result['message'] = 'Line would be inserted (check mode)'
        else:
            result['message'] = 'Line would be removed (check mode)'

    result['changed'] = changed
    module.exit_json(**result)

if __name__ == '__main__':
    main()
