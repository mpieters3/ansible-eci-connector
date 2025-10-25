run_tests_no_ip:
	ansible-playbook -vvv test/demo.yml

# Assumes you're hosting the ec2 publically
run_tests:
	@echo "Detecting public IP..."
	IP=$$(python3 -c "import urllib.request,sys;print(urllib.request.urlopen('https://api.ipify.org').read().decode())");
	
	echo $$IP; echo $$IP
	ansible-playbook -vvv test/demo.yml -e "myip=$$IP"