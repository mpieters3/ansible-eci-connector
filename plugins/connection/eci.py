DOCUMENTATION = '''
    connection: eci
    short_description: use ec2-instance-connect to support the ansible ssh module
    description:
        - This connection plugin extends the ssh module and uses ec2-instance-connect to handle access permissions
    author: mpieters
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
      aws_region:
          description: The AWS region to use. If not specified then the value of the AWS_REGION or EC2_REGION environment variable, if any, is used. See http://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region
          ini:
            - section: defaults
              key: aws_region
          env:
            - name: ANSIBLE_AWS_REGION
          vars:
            - name: aws_region
      instance_id:
          description: ec2-instance-id to connect to
          ini:
            - section: defaults
              key: instance_id
          vars:
            - name: ansible_instance_id
      availability_zone:
          description: availability_zone to connect to
          ini:
            - section: defaults
              key: availability_zone
          env:
            - name: ANSIBLE_AVAILABILITY_ZONE
          vars:
            - name: ansible_availability_zone
      host:
          description: Hostname/ip to connect to.
          default: inventory_hostname
          vars:
               - name: ansible_host
               - name: ansible_ssh_host
      host_key_checking:
          description: Determines if ssh should check host keys
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
      ssh_args:
          description: Arguments to pass to all ssh cli tools
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
          description: Common extra args for all ssh CLI tools
          ini:
              - section: 'ssh_connection'
                key: 'ssh_common_args'
                version_added: '2.7'
          env:
              - name: ANSIBLE_SSH_COMMON_ARGS
                version_added: '2.7'
          vars:
              - name: ansible_ssh_common_args
      ssh_executable:
          default: ssh
          description:
            - This defines the location of the ssh binary. It defaults to ``ssh`` which will use the first ssh binary available in $PATH.
            - This option is usually not required, it might be useful when access to system ssh is restricted,
              or when using ssh wrappers to connect to remote hosts.
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
            - This defines the location of the sftp binary. It defaults to ``sftp`` which will use the first binary available in $PATH.
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
            - This defines the location of the scp binary. It defaults to `scp` which will use the first binary available in $PATH.
          env: [{name: ANSIBLE_SCP_EXECUTABLE}]
          ini:
          - {key: scp_executable, section: ssh_connection}
          version_added: "2.6"
          vars:
              - name: ansible_scp_executable
                version_added: '2.7'
      scp_extra_args:
          description: Extra exclusive to the ``scp`` CLI
          vars:
              - name: ansible_scp_extra_args
          env:
            - name: ANSIBLE_SCP_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: scp_extra_args
              section: ssh_connection
              version_added: '2.7'
      sftp_extra_args:
          description: Extra exclusive to the ``sftp`` CLI
          vars:
              - name: ansible_sftp_extra_args
          env:
            - name: ANSIBLE_SFTP_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: sftp_extra_args
              section: ssh_connection
              version_added: '2.7'
      ssh_extra_args:
          description: Extra exclusive to the 'ssh' CLI
          vars:
              - name: ansible_ssh_extra_args
          env:
            - name: ANSIBLE_SSH_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: ssh_extra_args
              section: ssh_connection
              version_added: '2.7'
      retries:
          # constant: ANSIBLE_SSH_RETRIES
          description: Number of attempts to connect.
          default: 3
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
          default: 22
          ini:
            - section: defaults
              key: remote_port
          env:
            - name: ANSIBLE_REMOTE_PORT
          vars:
            - name: ansible_port
            - name: ansible_ssh_port
      remote_user:
          description:
              - User name with which to login to the remote server, normally set by the remote_user keyword.
              - If no user is supplied, Ansible will let the ssh client binary choose the user as it normally
          ini:
            - section: defaults
              key: remote_user
          env:
            - name: ANSIBLE_REMOTE_USER
          vars:
            - name: ansible_user
            - name: ansible_ssh_user
      pipelining:
          default: ANSIBLE_PIPELINING
          description:
            - Pipelining reduces the number of SSH operations required to execute a module on the remote server,
              by executing many Ansible modules without actual file transfer.
            - This can result in a very significant performance improvement when enabled.
            - However this conflicts with privilege escalation (become).
              For example, when using sudo operations you must first disable 'requiretty' in the sudoers file for the target hosts,
              which is why this feature is disabled by default.
          env:
            - name: ANSIBLE_PIPELINING
            #- name: ANSIBLE_SSH_PIPELINING
          ini:
            - section: defaults
              key: pipelining
            #- section: ssh_connection
            #  key: pipelining
          type: boolean
          vars:
            - name: ansible_pipelining
            - name: ansible_ssh_pipelining
      private_key_file:
          description:
              - Path to private key file to use for authentication
          ini:
            - section: defaults
              key: private_key_file
          env:
            - name: ANSIBLE_PRIVATE_KEY_FILE
          vars:
            - name: ansible_private_key_file
            - name: ansible_ssh_private_key_file
      control_path:
        description:
          - This is the location to save ssh's ControlPath sockets, it uses ssh's variable substitution.
          - Since 2.3, if null, ansible will generate a unique hash. Use `%(directory)s` to indicate where to use the control dir path setting.
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
          - Also, provides the `%(directory)s` variable for the control path setting.
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
      scp_if_ssh:
        default: smart
        description:
          - "Prefered method to use when transfering files over ssh"
          - When set to smart, Ansible will try them until one succeeds or they all fail
          - If set to True, it will force 'scp', if False it will use 'sftp'
        env: [{name: ANSIBLE_SCP_IF_SSH}]
        ini:
        - {key: scp_if_ssh, section: ssh_connection}
        vars:
          - name: ansible_scp_if_ssh
            version_added: '2.7'
      use_tty:
        version_added: '2.5'
        default: 'yes'
        description: add -tt to ssh commands to force tty allocation
        env: [{name: ANSIBLE_SSH_USETTY}]
        ini:
        - {key: usetty, section: ssh_connection}
        type: bool
        vars:
          - name: ansible_ssh_use_tty
            version_added: '2.7'
'''

import importlib
import os
import time

try:
  from ansible.utils.display import Display
  HAS_ANSIBLE = True
except ImportError:
  HAS_ANSIBLE = False

try:
    import boto3
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
    
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

import tempfile
from datetime import datetime

## we're going to base our connector off the basic SSH connector, as we want nearly all its behavior
ssh = importlib.import_module('ansible.plugins.connection.ssh')
display = Display()

ECI_PUSH_EXPIRY = 45
ECI_KEY_SIZE = 2048
ECI_KEY_EXPONENT = 65537

class Connection(ssh.Connection):
    """ SSH connection that uses EC2 Instance Connect to connect """

    transport = 'eci'
    has_pipelining = True

    def __init__(self, *args, **kwargs):
        ssh.Connection.__init__(self, *args, **kwargs)
        self.set_options()

        if self._play_context.private_key_file:
          display.vvv("EXISTING PRIVATE KEY FILE AVAILABLE, USING IT")
          self._private_key = load_pem_private_key(self._play_context.private_key_file, None, default_backend())
        else:
          display.vvv("NO PRIVATE KEY FILE, GENERATING ON DEMAND")
          (self._play_context.private_key_file, self._private_key) = self._create_temporary_key()

        self._public_key = self._private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')

        self._last_key_push = datetime.min
    
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
      display.vvv("TEMPORARY KEY LOCATION: {0}".format(file.name))
      return (file.name, key)

    def _bare_run(self, cmd, in_data, sudoable=True, checkrc=True):
      if((datetime.now() - self._last_key_push).total_seconds() > ECI_PUSH_EXPIRY):
          display.vvv("ECI PUB KEY EXPIRING/NOT SENT, PUSHING NOW")
          eci_args = {
            "InstanceId": self.get_option('instance_id'), 
            "InstanceOSUser": self._play_context.remote_user,
            "SSHPublicKey": self._public_key,
            "AvailabilityZone": self.get_option('availability_zone')
          }
          aws_client_args = {
            "region_name": self.get_option('aws_region'),
            "aws_secret_access_key": self.get_option('aws_secret_key'),
            "aws_access_key_id": self.get_option('aws_access_key')
          }

          _push_key(eci_args, aws_client_args)
          self._last_key_push = datetime.now()

      return ssh.Connection._bare_run(self, cmd=cmd, in_data=in_data, sudoable=sudoable, checkrc=checkrc)

def _push_key(eci_args, aws_client_args):
  client = boto3.client('ec2-instance-connect', **aws_client_args)
  client.send_ssh_public_key(**eci_args)