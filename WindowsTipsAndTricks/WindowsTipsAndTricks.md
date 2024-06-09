% Windows Tips and Tricks

Using Ansible with Windows can be an unfamiliar environment due to the differences in connections used and how Windows works compared to the typical Linux host.

This post will go through a few tips and tricks I've learnt about managing a Windows host with Ansible that could be useful for others.

# Try out become for delegation problems
One of the more common problems people encounter when using Ansible and Windows is the double hop/credential delegation issue.
This is when the Ansible task running on the Windows host is unable to delegate its credentials to downstream servers, like a fileshare, causing the task to fail.
While there are a few connection plugin specific options to solve this problem, [Ansible Become](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become-and-windows) is a common way to solve this problem that requires no changes to your connection settings.

Some common scenarios where become can help is copying a file from a network share, installing a program where the installer is on a network share, or importing a pfx and private key into the certificate store using [ansible.windows.win_certificate_store](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_certificate_store_module.html).

```yaml
- name: Copy file from network share
  ansible.windows.win_copy:
    src: \\fs\share\installer.exe
    dest: C:\Program Files\MyInstaller\installer.exe
    remote_src: true
  become: true
  become_method: runas
  vars:
    ansible_become_user: '{{ ansible_user }}'
    ansible_become_pass: '{{ ansible_password }}'

- name: Install program from network share
  ansible.windows.win_package:
    path: \\fs\share\installer.msi
    state: present
  become: true
  become_method: runas
  # Good when all you need to do is change the credentials used for network
  # delegation and not the local task.
  become_flags: logon_type=new_credentials logon_flags=netcredentials_only
  vars:
    ansible_become_user: FS\username
    ansible_become_pass: '{{ vaulted_password_var }}'

- name: Import pfx into the user's store
  ansible.windows.win_certificate_store:
    path: C:\Windows\TEMP\cert.pfx
    password: '{{ pfx_password_var }}'
    state: present
    key_exportable: false
    key_storage: user
    store_location: CurrentUser
    store_name: My
  become: true
  become_method: runas
  vars:
    ansible_become_user: '{{ ansible_user }}'
    ansible_become_pass: '{{ ansible_password }}'
```

# When testing code interactively, do so through Enter-PSSession
Running tasks in Ansible runs in a network logon that can cause unexpected issues that may not occur if the task is run manually in an interactive logon like RDP.
If troubleshooting a task that fails in Ansible but works interactively, try testing your command through `Enter-PSSession` against the target Windows host or with an SSH session.

```
# On a Windows host
Enter-PSSession target-windows

# Run the commands to test

# Or by using SSH
ssh username@DOMAIN.COM@target-windows

# Run the commands to test
```

By using `Enter-PSSession` or `ssh` you are replicating the same environment in which Ansible runs its tasks in and so should encounter the same issues.
See the point on become above to find a way to avoid these problems and run Ansible tasks in an environment similar to an interactive session.

# Try out the psrp connection plugin over winrm
The [psrp](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/psrp_connection.html) connection plugin is a newer connection plugin than [winrm](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/winrm_connection.html) and provides a few benefits like it being slightly faster, has better proxy support, and includes better Kerberos integration over `winrm`.
Both `psrp` and `winrm` work over the WinRM protocol so the same firewall rules and other Windows host setup options will be the same for either connection plugin.

While not an exhaustive list of the different options between the two plugins, the following table shows you the equivalent `psrp` options for each `winrm` one.

|WinRM|PSRP|Purpose|
|-|-|-|
|`ansible_connection=winrm`|`ansible_connection=psrp`|Changes the connection plugin used|
|`ansible_winrm_transport`|`ansible_psrp_auth`|Sets the authentication protocol, `basic`, `certificate`, `ntlm`, `kerberos`, `credssp`, psrp also offers `negotiate`|
|`ansible_winrm_scheme`|`ansible_psrp_protocol`|Sets the WinRM HTTP protocol, `http` or `https`|
|`ansible_winrm_server_cert_validation`|`ansible_psrp_cert_validation`|Can be set to `ignore` to ignore self signed certificates|
|`ansible_winrm_message_encryption`|`ansible_psrp_message_encryption`|Set the HTTP message encryption settings to `always`, `never`, or `auto`|
|`ansible_winrm_kerberos_delegation`|`ansible_psrp_negotiate_delegate`|Configure Kerberos auth to use unconstrained delegation or not|
|`ansible_winrm_kerberos_hostname_override`|`ansible_psrp_negotiate_hostname_override`|Change the Kerberos SPN name to use for authentication|

# Favour loops over individual tasks if running the same module
One of the causes behind Ansible taking time to run a command is that it needs to create the connection, authenticate the user, start the PowerShell process, and send across the data to run on each task.
Creating the connection and authentication can take some time to complete and by using a loop on the task it can avoid those steps and reuse the connection for each loop iteration.
The time improvements are even more pronounced when using the `psrp` connection plugin because starting a new process is a lot cheaper than on `winrm` and it no longer needs to recreate the connection for every task.
One caveat is that this can only be done when multiple tasks are using the same module, for example using [ansible.windows.win_regedit](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_regedit_module.html) to set multiple registry values.

For example instead of a list of tasks like this:

```yaml
- name: Change reg key 1
  ansible.windows.win_regedit:
    path: HKLM:\SOFTWARE\Foo
    name: Bar
    data: testing
    state: present

- name: Change reg key 2
  ansible.windows.win_regedit:
    path: HKCU:\SOFTWARE\Bar
    name: Foo
    data: Hello World
    state: present
```

You can combine this into one task

```yaml
- name: Change reg keys
  ansible.windows.win_regedit:
    path: '{{ item.path }}'
    name: '{{ item.name }}'
    data: '{{ item.data }}'
    state: present
  loop:
  - path: HKLM:\SOFTWARE\Foo
    name: Bar
    data: testing
  - path: HKCU:\SOFTWARE\Bar
    name: Foo
    data: Hello World
```

# Utilise DSC resources if available through ansible.windows.win_dsc
If there is not a native Ansible Windows module to perform a task you need, try looking at [ansible.windows.win_dsc](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_dsc_module.html) instead.
Windows DSC has a few [builtin resources](https://learn.microsoft.com/en-us/powershell/dsc/resources/resources?view=dsc-1.1) as well as many [community resources](https://github.com/dsccommunity) that can be used like Ansible modules to perform a task.

For example the [DSC File Resource](https://learn.microsoft.com/en-us/powershell/dsc/reference/resources/windows/fileresource?view=dsc-1.1) can be used to manage files and directories like [ansible.windows.win_file](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_file_module.html):

```yaml
- name: Create a directory using win_file
  ansible.windows.win_file:
    path: C:\Program Files\Foo
    state: directory

- name: Create a directory using win_dsc
    resource_name: File
    DestinationPath: C:\Program Files\foo
    Type: Directory
    Ensure: Present
```

The `win_dsc` resource requires the `resource_name` option to be set to the DSC resource to use, all other options align to the DSC resource that was specified by `resource_name`.

# Try ansible.windows.win_powershell for short PowerShell scripts over win_shell
The [ansible.windows.win_powershell](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_powershell_module.html) is a new module that can be used to run PowerShell scripts and provide objects as a return value rather than strings. Using `win_powershell` over [ansible.windows.win_shell](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_shell_module.html#ansible-collections-ansible-windows-win-shell-module) provides the following benefits of `win_shell`:

+ Provide arguments as objects rather than trying to embed them in a string, no need to worry about safely escaping and injection problems
+ Return value are also objects, no need to parse them again in Ansible
+ Can run in check mode if the script marks it as supported
+ Can change the module's `changed` result inside the script
+ Can provide diff output

Using `win_powershell` is essentially a way to run a short snippet of code as a mini module.
For example here is a short script that sets a WinRM authentication option which supports both check mode and returning a value back to Ansible.

```yaml
- name: Set WinRM Auth option
  ansible.windows.win_powershell:
    script: |
      [CmdletBinding(SupportsShouldProcess)]  # Marks this can run in check mode
      param (
          [string]$Option,
          [string]$State
      )

      $currentState = Get-Item "WSMan:\localhost\Service\Auth\$Option"
      if ($currentState.Value -ne $State) {
          # Only make change when not in check mode
          if ($Ansible.CheckMode) {
              Set-Item "WSMan:\localhost\Service\Auth\$Option" -Value $State
          }
      }
      else {
          # No change was needed, report that back as the module
          # results.
          $Ansible.Changed = $false
      }

      # Output the new state as a return result
      Get-Item "WSMan:\localhost\Service\Auth\$Option" |
        Select-Object Name, Value, SourceOfValue

    parameters:
      Option: Certificate
      State: true
  register: powershell_result

- ansible.builtin.debug:
    msg: >-
      Ansible WinRM Service Auth {{ powershell_result.output[0].Name }} was
      {{ (powershell_result.output[0].Value == 'true') | ternary("enabled", "disabled") }}
```

# Use module reboot option over win_reboot if available
A common scenario in Windows is needing to reboot the Windows host after performing a task.
This is typically done using the [ansible.windows.win_reboot](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_reboot_module.html), for example:

```yaml
- name: Install IIS Web-Server
  ansible.windows.win_feature:
    name: Web-Server
  register: iis_install

- name: Reboot when Web-Server feature requires it
  ansible.windows.win_reboot:
  when: iis_install.reboot_required
```

Some modules offer the ability to perform the reboot inside the same task, for example [ansible.windows.win_updates](https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_updates_module.html) has a `reboot` option.
Instead of using a separate `win_reboot` task use the module option for `reboot` if the module supports it, for example:

```yaml
- name: Install updates
  ansible.windows.win_updates:
    category_names: '*'
    reboot: true
    state: installed
```

A benefit of using the builtin `reboot` option of a module is it typically can perform extra checks before and after a reboot to ensure the host is in a good state and ready to be used again.
A task may also require multiple reboots to perform the action required and can handle those reboots automatically if given permission to do so.
For example the [microsoft.ad.domain](https://docs.ansible.com/ansible/latest/collections/microsoft/ad/domain_module.html) may require the host to be rebooted before the domain promotion is performed and also once more after the promotion is done.
By specifying `reboot: true` with that module it can do both of those reboots automatically rather than fail.

Not all modules support this feature, the module docs will indicate if this is possible or not.

# Use Kerberos in domain environments for secure and faster auth
When managing Windows hosts that are part of a domain environment, look at using Kerberos auth for a faster and easier to manage authentication option.
Kerberos authentication is safe to use over a HTTP connection as it encrypts the data using a strong AES cipher and it performs server name validation.
This means you don't need to worry about setting up a HTTPS listener and installing certificates to secure the connection when using Kerberos authentication.

The pre-requisites needed for Kerberos auth are:

+ The Windows host is domain joined
+ You are authenticating with a domain user
+ The Ansible host has the Python Kerberos libraries installed
+ The Ansible host has a `/etc/krb5.conf` file configured with the domain information

It is not a requirement for the Ansible host to be joined to the domain, it just needs to know how to contact the Kerberos Key Distribution Center (KDC) otherwise known as a domain controller in Active Directory.
This can either be configured through DNS SRV records or done explicitly in the `/etc/krb5.conf` file
A basic `krb5.conf` file is:

```ini
[libdefaults]
  # Not required but useful to have a default realm
  default_realm = domain.test

  # Can set to true to lookup the kdc based on the
  # DNS SRV records
  dns_lookup_kdc = false

[realms]
  # Set the KDC to use for a particular realm
  # This is not required if DNS is configured
  DOMAIN.TEST = {
    kdc = dc.domain.test
  }

[domain_realms]
  # Map the hostname prefixes to a realm configuration
  # This is not required if DNS is configured
  .domain.test = DOMAIN.TEST
  domain.test = DOMAIN.TEST
```

A quick test to ensure the Ansible host can work with Kerberos is to run `kinit username@DOMAIN.TEST`.
If DNS is not being used to find the realm KDC, the domain portion after `@` is case sensitive and needs to match the entry under `[realms]`.
If the KDC can be contacted `kinit` will prompt for the user's password, otherwise it will fail.

# Try out microsoft.ad.ldap as your inventory source
The [microsoft.ad.ldap](https://docs.ansible.com/ansible/latest/collections/microsoft/ad/ldap_inventory.html) inventory plugin can be used to dynamically build your Ansible inventory based on the hosts joined to the domain controller.
The default inventory configuration is set to retrieve all computer accounts and set the `inventory_hostname` to the LDAP `name` attribute and the `ansible_host` connection var set to the LDAP `dNSHostName` attribute.
It is also possible to retrieve extra LDAP attributes to store as variables on the host and derive Ansible group membership based on the computer account information.

For example the below configuration is used to

+ Retrieve all computer accounts in the default domain realm
+ Set the `computer_membership` hostvar to a list of groups the computer account is a member of
+ Set the `parent_ou` hostvar to the LDAP container name the computer account is stored in
+ Place all retrieved hosts in the `windows` group
+ Place the host in a group named after each group it's a member of (`computer_membership`)
+ Place the host in a group named after the container it is stored in (`parent_ou`)

```yaml
plugin: microsoft.ad.ldap

attributes:
  memberOf:
    computer_membership: this | microsoft.ad.parse_dn | map(attribute="0.1")

compose:
  parent_ou: >-
    (microsoft_ad_distinguished_name | microsoft.ad.parse_dn)[1][1]

groups:
  windows: true

keyed_groups:
- key: computer_membership | default([]) | lower
  default_value: ungrouped
  separator: ""
- key: parent_ou | default("") | lower
  default_value: ungrouped
  separator: ""
```

An example inventory listing using the above configuration is:

```yaml
# ansible-inventory --list -i microsoft.ad.ldap.yml --yaml
all:
  children:
    cert_publishers:
      hosts:
        DC01: {}
    domain_controllers:
      hosts:
        DC01: {}
    pre_windows_2000_compatible_access:
      hosts:
        DC01: {}
    servers:
      hosts:
        SERVER2022: {}
    windows:
      hosts:
        DC01:
          ansible_host: DC01.domain.test
          computer_membership:
          - Pre-Windows 2000 Compatible Access
          - Cert Publishers
          microsoft_ad_distinguished_name: CN=DC01,OU=Domain Controllers,DC=domain,DC=test
          parent_ou: Domain Controllers
        SERVER2022:
          ansible_host: SERVER2022.domain.test
          computer_membership: []
          microsoft_ad_distinguished_name: CN=SERVER2022,OU=Servers,DC=domain,DC=test
          parent_ou: Servers
```
