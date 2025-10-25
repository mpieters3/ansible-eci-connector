# EC2 Instance Connect Connection Plugin for Ansible

The EC2 Instance Connect (ECI) connection plugin was created to take advantage of AWS's <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html">ECI</a> capability Rather than rely on public keys statically stored on resources, this allows us to take advantage of using AWS native roles and permissions to access and manage linux servers instead.

This is helpful in situations where you need to use continue to use ansible over AWS native instance management solutions, but want to take advantage of AWS's native IAM model for authorization as well as to avoid sharing of long living private keys.

Check [releases](https://github.com/mpieters3/ansible-eci-connector/releases) for versions of this library for older Ansible versions

## Installation into Ansible

Drop eci.py into a connection plugin location, as outlined in https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html. Must have boto3 and ec2instanceconnectcli python libraries available

AWS Servers must be set up to support <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html">EC2 Instance Connect</a>.

### Parameters

For parameter details, use ansible-doc -t connection eci

In general, aligned to the same requirements as most other <a href="https://docs.ansible.com/ansible/latest/modules/ec2_module.html">aws related modules and tasks in ansible</a>. Namely, in one way or another AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set, and we must also have region. Generally, this is set either at the host level or globally.

The connection plugin can take either `instance_id` or use `ip address` (public or private) or hostname to determine the correct connection details.

## Local Development

This is setup to use a VSCode devcontainer, so as long as you install VScode's devcontainer plugin, it should set up easily.

Make sure the plugin is being pulled in correctly... from the workspace directory, run the following command to make sure you're getting the connection info:
`ansible-doc -t connection eci`

### Testing the plugin

The [demo.yml](./test/demo.yml) tests this plugin by doing a few things:

1. Create a security group (opening port 22 from 0.0.0.0/0)
2. Creates a t2.micro aws linux ami; doesn't set any keypair, so not accessible with 'normal' ssh
3. Connects using eci with instance-id & ip address (preferred) information as root, echo basic message
4. Connects using eci with ip address host information as ec2-user, echo basic message

### Running playbook with debug

Create a .env file and set your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for your test AWS account.
Use vscode's debug launch to `Debug demo.yml (run_playbook in Python)` - breakpoints in `eci.py` will be honored.

Alternatively, you can use the Makefile `run_tests`

## TODO

- Look at incorporating into or deprecating in favor of [ansible-collections/community.aws](https://github.com/ansible-collections/community.aws)
- - The S3 bucket does add additional complexity that this avoids...
