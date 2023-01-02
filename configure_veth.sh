 sudo ip link add xdptut-aaaa type veth peer name veth1
 sudo ip link set veth1 netns xdptut-697b
 sudo ip a add 10.11.2.1/24 dev xdptut-aaaa
 sudo ip link set up dev xdptut-aaaa