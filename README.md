# EC2 Instance Connect Connection Plugin for Ansible

The EC2 Instance Connect (ECI) connection plugin was created to take advantage of AWS's <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html">ECI</a> capability Rather than rely on public keys statically stored on resources, this allows us to take advantage of using AWS native roles and permissions to access and manage linux servers instead. 

This is helpful in situations where you need to use continue to use ansible over AWS native instance management solutions, but want to take advantage of AWS's native IAM model for authorization as well as to avoid sharing of long living private keys.

## Installation into Ansible
Drop eci.py into a connection plugin location, as outlined in https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html

AWS Servers must be set up to support <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html">EC2 Instance Connect</a>. 

### Parameters
For parameter details, use ansible-doc -t connection eci

In general, aligned to the same requirements as most other <a href="https://docs.ansible.com/ansible/latest/modules/ec2_module.html">aws related modules and tasks in ansible</a>. Namely, in one way or another AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set, and we must also have region. Generally, this is set either at the host level or globally.

TODO: 
The connection plugin can take either instance_id or use ip address (public or private) or hostname to determine the correct connection details. 

## Container development / local testing
Development / Local testing set up up to be with Visual Studio Code using its devcontainer.json with a DockerFile that includes Ansible, Python3, Boto3, and AWS CLI. This is largely as this was used as a one stop dev container, but should be easy to run in docker even without visual studio code.

This does create a publically accessible security group, so use wisely. 

### Demo summary
1. Create a security group (opening port 22 from 0.0.0.0/0)
2. Creates a t2.micro aws linux ami; doesn't set any keypair, so not accessible with 'normal' ssh
3. Connects using eci with instance-id & ip address (preferred) information as root, echo basic message
4. Connects using eci with ip address host information as ec2-user, echo basic message

### Running playbook
Once in container, run the following commands to demonstrate.


```
export AWS_ACCESS_KEY_ID='<<YOUR_ACCESS_KEY_ID>>'
export AWS_SECRET_ACCESS_KEY='<<YOUR_SECRET_ACCESS_KEY>>'
cd /workspaces/ansible-eci-connector/test
ansible-playbook demo.yml

```

## Why not MSSH? 
While <a href="https://github.com/mingbowan/mssh/blob/master/mssh.py">mssh</a> may be an option as well, it was important to ensure better support for everything the original SSH provider has

## TODO
- IP Address to instance id (or vice versa?) lookup
- Handle boto3 / other requirements missing cleanly
- Align requirements to better follow ansible plugin standards
- remove temp keys when run finishes
- persist temp key across tasks? 
- Add a docker compose file to run without Visual Studio Code