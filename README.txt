#Required python Modules
netfilterqueue as netq
capy
optparse
argparse(for python 3)

**NOTE
If targeting the same machine
Open Terminal
>iptables -I OUTPUT -j NFQUEUE --queue-num 0
>iptables -I INPUT -j NFQUEUE --queue-num 0

If targeting a remote machine
Open Terminal
>iptables -I FORWARD -j NFQUEUE --queue-num 0


AFTER Experiment
Open Terminal
>iptables --flush