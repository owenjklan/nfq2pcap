# nfq2pcap
Proof-of-concept to read packets from an NFQUEUE and write them to a pcap file.

## Example iptables rules for testing
For packets coming from www.example.com:
`iptables -t raw -I PREROUTING -s `dig -t a www.example.com +short` -j NFQUEUE --queue-num 100 --queue-bypass`

For packets going to www.example.com:
`iptables -t raw -I OUTPUT -d `dig -t a www.example.com +short` -j NFQUEUE --queue-num 100 --queue-bypass`

## Usage information
```owen@pfhor:~/c/nfq2pcap$ ./nfq2pcap -h
USAGE:
  ./nfq2pcap [-o filename] [-q queue] [-t target] [-v verdict]

Options:
  -o filename  Name of output pcap file. Default: output.pcap

  -q queue     NFQUEUE ID to read packets from. Default: 0

  -t target    NFQUEUE ID to read packets from. Default: 1

  -v verdict   Netfilter verdict code to use for packets. Default: 1

Valid values for verdict are:
  NF_DROP    0
  NF_ACCEPT  1
  NF_QUEUE   3

```
