# nfq2pcap
Proof-of-concept to read packets from an NFQUEUE and write them to a pcap file.

## Example iptables rules for testing
For packets coming from www.example.com:
```iptables -t raw -I PREROUTING -s `dig -t a www.example.com +short` -j NFQUEUE --queue-num 100 --queue-bypass```

For packets going to www.example.com:
```iptables -t raw -I OUTPUT -d `dig -t a www.example.com +short` -j NFQUEUE --queue-num 100 --queue-bypass```

## Usage information
```owen@pfhor:~/c/nfq2pcap$ ./nfq2pcap -h
USAGE:
  ./nfq2pcap [-h] [-6] [-o filename] [-q queue] [-t target] [-v verdict]

Options:
  -6           Capture as RAW IPv6 packets.

  -h           Display usage information / help.

  -o filename  Name of output pcap file. Default: output.pcap

  -q queue     NFQUEUE ID to read packets from. Default: 0

  -t target    NFQUEUE ID to read packets from. Default: 1

  -v verdict   Netfilter verdict code to use for packets. Default: 1

Valid values for verdict are:
  NF_DROP    0
  NF_ACCEPT  1
  NF_QUEUE   3

```
## Pass-thru configuration
nfq2pcap can be used in a "pass-thru" configuration. Using a verdict of NF_QUEUE (3) and the `-t target`
command line option, packets can be read off the listening queue, written to the pcap file and then
sent on to the Netfilter queue specified by `target`. Great for stepping in front of an existing NFQUEUE
using service to capture what it sees coming in, without disrupting it's operation.

Example:
```./nfq2pcap -v 3 -q 100 -t 200 -o mitm.pcap```
The above example will read packets from queue #100, write them to `mitm.pcap` and then send the packets on to
queue #200.
