#EC2 Instance Connect Connection Plugin for Ansible

The EC2 Instance Connect (ECI) connection plugin was created to take advantage of AWS's <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html">ECI</a> capability Rather than rely on public keys statically stored on resources, this allows us to take advantage of using AWS native roles and permissions to access and manage linux servers instead. 


##Running
(TODO but in general):
Drop eci.py into ~/.ansible/plugins/connection/


##TODO
-Better README.md
-Build a docker file to testing ECI for ansible
-IP Address to instance id (or vice versa?) lookup
-Handle boto3 / other requirements missing cleanly
-Align requirements to better follow ansible plugin standards
-remove temp keys
-persist temp key across tasks? 