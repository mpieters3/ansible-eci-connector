DOCUMENTATION = '''
    connection: eci
    short_description: use ec2-instance-connect to support the ansible ssh module
    description:
        - This connection plugin extends the ssh module and uses ec2-instance-connect to handle access permissions
    requirements:
      - The remote EC2 Instance must be configured for ec2 instance connect
      - Must have boto3 and cryptography
    author: mpieters3
    options:
      aws_access_key:
          description: AWS access key. If not set then the value of the AWS_ACCESS_KEY_ID, AWS_ACCESS_KEY or EC2_ACCESS_KEY environment variable is used.
          ini:
            - section: defaults
              key: aws_access_key
          env:
            - name: ANSIBLE_AWS_ACCESS_KEY
          vars:
            - name: aws_access_key
      aws_secret_key:
          description: AWS secret key. If not set then the value of the AWS_SECRET_ACCESS_KEY, AWS_SECRET_KEY, or EC2_SECRET_KEY environment variable is used.
          ini:
            - section: defaults
              key: aws_secret_key
          env:
            - name: ANSIBLE_AWS_SECRET_KEY
          vars:
            - name: aws_secret_key
      profile:
          description: The name of a AWS profile to use. If not given, then the default profile is used.
          ini:
            - section: defaults
              key: profile
          env:
            - name: ANSIBLE_AWS_PROFILE
          vars:
            - name: profile
            - name: aws_profile
      role_arn:
          description: AWS role arn for STS assume-role.
          ini:
            - section: defaults
              key: role_arn
          env:
            - name: ANSIBLE_AWS_ROLE_ARN
          vars:
            - name: role_arn
            - name: aws_role_arn
      region:
          description: The AWS region to use. If not specified then the value of the AWS_REGION or EC2_REGION environment variable, if any, is used. See http://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region
          ini:
            - section: defaults
              key: region
          env:
            - name: AWS_REGION
            - name: EC2_REGION
          vars:
            - name: ansible_region
            - name: aws_region
            - name: ec2_region
      instance_id:
          description: ec2-instance-id to connect to, will be looked up if not provided
          ini:
            - section: defaults
              key: instance_id
          vars:
            - name: ansible_instance_id
      availability_zone:
          description: availability zone for the ec2 instance, will be looked up if not provided
          ini:
            - section: defaults
              key: availability_zone
          vars:
            - name: ansible_availability_zone
          version_added: 2.12.0
      disable_caching:
          description: Disables caching of eci key/push metadata between requests
          default: False
          ini:
            - section: defaults
              key: eci_disable_caching
          vars:
            - name: eci_disable_caching        
          version_added: 2.12.0
      host:
          description: Hostname/IP/Domain name to connect to.
          default: inventory_hostname
          vars:
               - name: inventory_hostname
               - name: ansible_host
               - name: ansible_ssh_host
               - name: delegated_vars['ansible_host']
               - name: delegated_vars['ansible_ssh_host']
      host_key_checking:
          description: Determines if SSH should check host keys.
          default: True
          type: boolean
          ini:
              - section: defaults
                key: 'host_key_checking'
              - section: ssh_connection
                key: 'host_key_checking'
                version_added: '2.5'
          env:
              - name: ANSIBLE_HOST_KEY_CHECKING
              - name: ANSIBLE_SSH_HOST_KEY_CHECKING
                version_added: '2.5'
          vars:
              - name: ansible_host_key_checking
                version_added: '2.5'
              - name: ansible_ssh_host_key_checking
                version_added: '2.5'
      password:
          description: Authentication password for the C(remote_user). Can be supplied as CLI option.
          vars:
              - name: ansible_password
              - name: ansible_ssh_pass
              - name: ansible_ssh_password
      sshpass_prompt:
          description:
              - Password prompt that sshpass should search for. Supported by sshpass 1.06 and up.
              - Defaults to C(Enter PIN for) when pkcs11_provider is set.
          default: ''
          ini:
              - section: 'ssh_connection'
                key: 'sshpass_prompt'
          env:
              - name: ANSIBLE_SSHPASS_PROMPT
          vars:
              - name: ansible_sshpass_prompt
          version_added: '2.10'
      ssh_args:
          description: Arguments to pass to all SSH CLI tools.
          default: '-C -o ControlMaster=auto -o ControlPersist=60s'
          ini:
              - section: 'ssh_connection'
                key: 'ssh_args'
          env:
              - name: ANSIBLE_SSH_ARGS
          vars:
              - name: ansible_ssh_args
                version_added: '2.7'
      ssh_common_args:
          description: Common extra args for all SSH CLI tools.
          ini:
              - section: 'ssh_connection'
                key: 'ssh_common_args'
                version_added: '2.7'
          env:
              - name: ANSIBLE_SSH_COMMON_ARGS
                version_added: '2.7'
          vars:
              - name: ansible_ssh_common_args
          cli:
              - name: ssh_common_args
          default: ''
      ssh_executable:
          default: ssh
          description:
            - This defines the location of the SSH binary. It defaults to C(ssh) which will use the first SSH binary available in $PATH.
            - This option is usually not required, it might be useful when access to system SSH is restricted,
              or when using SSH wrappers to connect to remote hosts.
          env: [{name: ANSIBLE_SSH_EXECUTABLE}]
          ini:
          - {key: ssh_executable, section: ssh_connection}
          #const: ANSIBLE_SSH_EXECUTABLE
          version_added: "2.2"
          vars:
              - name: ansible_ssh_executable
                version_added: '2.7'
      sftp_executable:
          default: sftp
          description:
            - This defines the location of the sftp binary. It defaults to C(sftp) which will use the first binary available in $PATH.
          env: [{name: ANSIBLE_SFTP_EXECUTABLE}]
          ini:
          - {key: sftp_executable, section: ssh_connection}
          version_added: "2.6"
          vars:
              - name: ansible_sftp_executable
                version_added: '2.7'
      scp_executable:
          default: scp
          description:
            - This defines the location of the scp binary. It defaults to C(scp) which will use the first binary available in $PATH.
          env: [{name: ANSIBLE_SCP_EXECUTABLE}]
          ini:
          - {key: scp_executable, section: ssh_connection}
          version_added: "2.6"
          vars:
              - name: ansible_scp_executable
                version_added: '2.7'
      scp_extra_args:
          description: Extra exclusive to the C(scp) CLI
          vars:
              - name: ansible_scp_extra_args
          env:
            - name: ANSIBLE_SCP_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: scp_extra_args
              section: ssh_connection
              version_added: '2.7'
          cli:
            - name: scp_extra_args
          default: ''
      sftp_extra_args:
          description: Extra exclusive to the C(sftp) CLI
          vars:
              - name: ansible_sftp_extra_args
          env:
            - name: ANSIBLE_SFTP_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: sftp_extra_args
              section: ssh_connection
              version_added: '2.7'
          cli:
            - name: sftp_extra_args
          default: ''
      ssh_extra_args:
          description: Extra exclusive to the SSH CLI.
          vars:
              - name: ansible_ssh_extra_args
          env:
            - name: ANSIBLE_SSH_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: ssh_extra_args
              section: ssh_connection
              version_added: '2.7'
          cli:
            - name: ssh_extra_args
          default: ''
      reconnection_retries:
          description: Number of attempts to connect.
          default: 0
          type: integer
          env:
            - name: ANSIBLE_SSH_RETRIES
          ini:
            - section: connection
              key: retries
            - section: ssh_connection
              key: retries
          vars:
            - name: ansible_ssh_retries
              version_added: '2.7'
      port:
          description: Remote port to connect to.
          type: int
          ini:
            - section: defaults
              key: remote_port
          env:
            - name: ANSIBLE_REMOTE_PORT
          vars:
            - name: ansible_port
            - name: ansible_ssh_port
          keyword:
            - name: port
      remote_user:
          description:
              - User name with which to login to the remote server, normally set by the remote_user keyword.
              - If no user is supplied, Ansible will let the SSH client binary choose the user as it normally.
          ini:
            - section: defaults
              key: remote_user
          env:
            - name: ANSIBLE_REMOTE_USER
          vars:
            - name: ansible_user
            - name: ansible_ssh_user
          cli:
            - name: user
          keyword:
            - name: remote_user
      pipelining:
          description:
            - Pipelining settings
          env:
            - name: ANSIBLE_PIPELINING
            - name: ANSIBLE_SSH_PIPELINING
          ini:
            - section: defaults
              key: pipelining
            - section: connection
              key: pipelining
            - section: ssh_connection
              key: pipelining
          vars:
            - name: ansible_pipelining
            - name: ansible_ssh_pipelining
      private_key_file:
          description:
              - Path to private key file to use for authentication.
          ini:
            - section: defaults
              key: private_key_file
          env:
            - name: ANSIBLE_PRIVATE_KEY_FILE
          vars:
            - name: ansible_private_key_file
            - name: ansible_ssh_private_key_file
          cli:
            - name: private_key_file
              option: '--private-key'
      control_path:
        description:
          - This is the location to save SSH's ControlPath sockets, it uses SSH's variable substitution.
          - Since 2.3, if null (default), ansible will generate a unique hash. Use ``%(directory)s`` to indicate where to use the control dir path setting.
          - Before 2.3 it defaulted to ``control_path=%(directory)s/ansible-ssh-%%h-%%p-%%r``.
          - Be aware that this setting is ignored if C(-o ControlPath) is set in ssh args.
        env:
          - name: ANSIBLE_SSH_CONTROL_PATH
        ini:
          - key: control_path
            section: ssh_connection
        vars:
          - name: ansible_control_path
            version_added: '2.7'
      control_path_dir:
        default: ~/.ansible/cp
        description:
          - This sets the directory to use for ssh control path if the control path setting is null.
          - Also, provides the ``%(directory)s`` variable for the control path setting.
        env:
          - name: ANSIBLE_SSH_CONTROL_PATH_DIR
        ini:
          - section: ssh_connection
            key: control_path_dir
        vars:
          - name: ansible_control_path_dir
            version_added: '2.7'
      sftp_batch_mode:
        default: 'yes'
        description: 'TODO: write it'
        env: [{name: ANSIBLE_SFTP_BATCH_MODE}]
        ini:
        - {key: sftp_batch_mode, section: ssh_connection}
        type: bool
        vars:
          - name: ansible_sftp_batch_mode
            version_added: '2.7'
      ssh_transfer_method:
        description:
            - "Preferred method to use when transferring files over ssh"
            - Setting to 'smart' (default) will try them in order, until one succeeds or they all fail
            - Using 'piped' creates an ssh pipe with C(dd) on either side to copy the data
        choices: ['sftp', 'scp', 'piped', 'smart']
        env: [{name: ANSIBLE_SSH_TRANSFER_METHOD}]
        ini:
            - {key: transfer_method, section: ssh_connection}
        vars:
            - name: ansible_ssh_transfer_method
              version_added: '2.12'
      scp_if_ssh:
        deprecated:
              why: In favor of the "ssh_transfer_method" option.
              version: "2.17"
              alternatives: ssh_transfer_method
        default: smart
        description:
          - "Preferred method to use when transferring files over SSH."
          - When set to I(smart), Ansible will try them until one succeeds or they all fail.
          - If set to I(True), it will force 'scp', if I(False) it will use 'sftp'.
          - This setting will overridden by ssh_transfer_method if set.
        env: [{name: ANSIBLE_SCP_IF_SSH}]
        ini:
        - {key: scp_if_ssh, section: ssh_connection}
        vars:
          - name: ansible_scp_if_ssh
            version_added: '2.7'
      use_tty:
        version_added: '2.5'
        default: 'yes'
        description: add -tt to ssh commands to force tty allocation.
        env: [{name: ANSIBLE_SSH_USETTY}]
        ini:
        - {key: usetty, section: ssh_connection}
        type: bool
        vars:
          - name: ansible_ssh_use_tty
            version_added: '2.7'
      timeout:
        default: 10
        description:
            - This is the default amount of time we will wait while establishing an SSH connection.
            - It also controls how long we can wait to access reading the connection once established (select on the socket).
        env:
            - name: ANSIBLE_TIMEOUT
            - name: ANSIBLE_SSH_TIMEOUT
              version_added: '2.11'
        ini:
            - key: timeout
              section: defaults
            - key: timeout
              section: ssh_connection
              version_added: '2.11'
        vars:
          - name: ansible_ssh_timeout
            version_added: '2.11'
        cli:
          - name: timeout
        type: integer
      pkcs11_provider:
        version_added: '2.12'
        default: ""
        description:
          - "PKCS11 SmartCard provider such as opensc, example: /usr/local/lib/opensc-pkcs11.so"
          - Requires sshpass version 1.06+, sshpass must support the -P option.
        env: [{name: ANSIBLE_PKCS11_PROVIDER}]
        ini:
          - {key: pkcs11_provider, section: ssh_connection}
        vars:
          - name: ansible_ssh_pkcs11_provider
'''

import hashlib
import importlib
import json
import os
import tempfile
from datetime import datetime
import socket
import ipaddress

from ansible.module_utils.basic import missing_required_lib
from ansible.errors import AnsibleConnectionFailure, AnsibleError

try:
    import boto3
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
    
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization.ssh import load_ssh_private_key
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

ssh = importlib.import_module('ansible.plugins.connection.ssh')

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


ECI_PUSH_EXPIRY = 45
ECI_KEY_SIZE = 2048
ECI_KEY_EXPONENT = 65537

ECI_CACHE_KEY_FILE = "key_file"
ECI_CACHE_LAST_PUSH = "last_push"
ECI_CACHE_PUBLIC_KEY = "public_key"
ECI_CACHE_REMOTE_USER = "remote_user"
ECI_CACHE_INSTANCE_ID = "instance_id"
ECI_CACHE_AZ = "availability_zone"
ECI_CACHE_PROFILE = "profile"
ECI_CACHE_ROLE_ARN = "role_arn"

ECI_CONNECTION_CACHE = {}

class Connection(ssh.Connection):
    """ SSH connection that uses EC2 Instance Connect to connect """

    transport = 'eci'
    has_pipelining = True

    def __init__(self, *args, **kwargs):
        if not HAS_BOTO:
          raise AnsibleError(missing_required_lib("boto3"))
        if not HAS_CRYPTOGRAPHY:
          raise AnsibleError(missing_required_lib("cryptography"))

        ssh.Connection.__init__(self, *args, **kwargs)
        self._load_name = self.__module__.split('.')[-1]
        self._ansible_playbook_pid = kwargs.get('ansible_playbook_pid')
        self.session = None

        self.set_options()

    def exec_command(self, cmd, in_data=None, sudoable=True):        
      self.set_option('private_key_file', self._get_eci_data()[ECI_CACHE_KEY_FILE])
      self.set_option('sshpass_prompt', '')
      self.set_option('password', None)
      return ssh.Connection.exec_command(self, cmd=cmd, in_data=in_data, sudoable=sudoable)

    def _bare_run(self, cmd, in_data, sudoable=True, checkrc=True):
      self._refresh_eci()
      return ssh.Connection._bare_run(self, cmd=cmd, in_data=in_data, sudoable=sudoable, checkrc=checkrc)

    def _cache_file_path(self):      
      cache_key = "%s_%s_%s" % (self._play_context.remote_addr, self._play_context.remote_user, self._ansible_playbook_pid)
      m = hashlib.sha1()
      m.update(bytes(cache_key, "utf-8"))
      digest = m.hexdigest()
      cache_file_path = os.path.join(tempfile.gettempdir(), digest[:10])
      display.vv("CACHE_FILE_PATH: %s" % cache_file_path)

      return cache_file_path

    def _refresh_eci(self):
      connection_metadata = self._get_eci_data()
      if (datetime.now().timestamp() - connection_metadata[ECI_CACHE_LAST_PUSH]) > ECI_PUSH_EXPIRY:
        display.vv("ECI PUB KEY EXPIRING/NOT SENT, PUSHING NOW %s-%s" % (connection_metadata[ECI_CACHE_REMOTE_USER], connection_metadata[ECI_CACHE_INSTANCE_ID]))
        self._push_key(connection_metadata)
        self._cache_eci_data(connection_metadata)

    def _cache_eci_data(self, connection_metadata):
      self._eci_data = connection_metadata
      if self.get_option('disable_caching'):
        return
      file_path = self._cache_file_path()
      with open(file_path, 'w') as outfile:
        json.dump(connection_metadata, outfile)

    def _get_eci_data(self):
      session = self._init_session()

      if hasattr(self, '_eci_data'):
        display.vvv("LOCAL ECI DATA EXISTS")
        return self._eci_data
      
      if not self.get_option('disable_caching'):
        ## check if a file already exists
        file_path = self._cache_file_path()
        if os.path.exists(file_path):
          display.vv("CACHED ECI DATA EXISTS")
          with open(file_path, 'r') as outfile:
            self._eci_data = json.load(outfile)
            return self._eci_data
        else:
          display.vv("NO CACHED ECI DATA EXISTS")

      if self._play_context.private_key_file:
        display.vv("EXISTING PRIVATE KEY FILE AVAILABLE, USING IT")
        private_key = load_ssh_private_key(open(self._play_context.private_key_file, 'rb').read(), None, default_backend())
        private_key_file = self._play_context.private_key_file
      else:
        display.vv("NO PRIVATE KEY FILE, GENERATING ON DEMAND")
        private_key_file, private_key = self._create_temporary_key()

        public_key = private_key.public_key().public_bytes(
          encoding=serialization.Encoding.OpenSSH,
          format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        cache_entry = {
          ECI_CACHE_KEY_FILE: private_key_file,
          ECI_CACHE_PUBLIC_KEY: public_key,
          ECI_CACHE_LAST_PUSH: 0,
          ECI_CACHE_REMOTE_USER: self._play_context.remote_user,
        }

      lookup_address = self._play_context.remote_addr
      try:
        ip = ipaddress.ip_address(lookup_address)
      except ValueError:
        lookup_address = socket.gethostbyname(lookup_address)
      if self.get_option('instance_id'):
        cache_entry[ECI_CACHE_INSTANCE_ID] = self.get_option('instance_id')
      else:
        client = session.client('ec2')
        display.vv("NO INSTANCE_ID PROVIDED, ATTEMPTING LOOKUP for %s" % lookup_address)
        for filter_name in ('ip-address', 'private-ip-address', 'private-dns-name'):
          filter = [{'Name': filter_name,'Values': [lookup_address ]}]
          response = client.describe_instances(Filters=filter)
          for r in response['Reservations']:
            for i in r['Instances']:
              cache_entry[ECI_CACHE_INSTANCE_ID] = i['InstanceId']
          ##We've found it, so stop
          if(ECI_CACHE_INSTANCE_ID in cache_entry):
            break

      if not ECI_CACHE_INSTANCE_ID in cache_entry:
        raise Exception('No instance_id found for %s' % lookup_address)
      
      if self.get_option('availability_zone'):
        cache_entry[ECI_CACHE_AZ] = self.get_option('availability_zone')
      else:
        display.vv("NO AVAILABILITY_ZONE PROVIDED, ATTEMPTING LOOKUP for %s" % lookup_address)
        client = session.client('ec2')
        response = client.describe_instances(InstanceIds=[cache_entry[ECI_CACHE_INSTANCE_ID]])
        for r in response['Reservations']:
          for i in r['Instances']:
            cache_entry[ECI_CACHE_AZ] = i['Placement']['AvailabilityZone']
          ##We've found it, so stop
          if ECI_CACHE_AZ in cache_entry:
            break
      self._cache_eci_data(cache_entry)

      return cache_entry

    def _create_temporary_key(self):
      key = rsa.generate_private_key(
          public_exponent=ECI_KEY_EXPONENT,
          key_size=ECI_KEY_SIZE,
          backend=default_backend()
      )
      pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
      )
      file = tempfile.NamedTemporaryFile(delete=False)
      with file as pem_out:
          pem_out.write(pem)
      display.vv("TEMPORARY KEY LOCATION: {0}".format(file.name))
      return (file.name, key)

    def _get_boto_args(self):
      if not hasattr(self, '_boto_args'):
        self._boto_args = {
            "region_name": self.get_option('region'),
            "profile_name": self.get_option('profile'),
            "aws_secret_access_key": self.get_option('aws_secret_key'),
            "aws_access_key_id": self.get_option('aws_access_key')
          }
      return self._boto_args

    def _aws_switch_role(self, role_arn):
      client = self.session.client('sts')
      response = client.assume_role(
          RoleArn=role_arn,
          RoleSessionName='ansible_eci'
      )
      return response.get("Credentials")

    def _init_session(self):
      if self.session == None:
        boto_args = self._get_boto_args()
        self.session = boto3.Session(**boto_args)

        if self.get_option('role_arn'):
          credential = self._aws_switch_role(self.get_option('role_arn'))
          self.session = boto3.Session(
            aws_access_key_id=credential["AccessKeyId"],
            aws_secret_access_key=credential["SecretAccessKey"],
            aws_session_token=credential["SessionToken"],
            region_name=self.get_option('region')
          )

      return self.session

    def _push_key(self, connection_metadata):
      session = self._init_session()
      client = session.client('ec2-instance-connect')
      client.send_ssh_public_key(
          InstanceId=connection_metadata[ECI_CACHE_INSTANCE_ID], 
          InstanceOSUser=connection_metadata[ECI_CACHE_REMOTE_USER],
          SSHPublicKey=connection_metadata[ECI_CACHE_PUBLIC_KEY],
          AvailabilityZone=connection_metadata[ECI_CACHE_AZ],
      )
      connection_metadata[ECI_CACHE_LAST_PUSH] = datetime.now().timestamp()
