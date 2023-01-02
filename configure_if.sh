for i in rx tx tso ufo gso gro lro tx nocache copy sg txvlan rxvlan; do
    sudo /sbin/ethtool -K eth1 $i off 2>&1 > /dev/null;
done