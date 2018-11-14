## Sniffer

a network packet sniffer like tcpdump but can filter packet content that only contain some specific key use -c option

## Build

install libpcap library

	CentOS
	yum install libpcap-devel

	Ubuntu
	apt-get install libpcap-dev
	
make 

## How to use

example: 

	./sniffer -i any -f capture.dat -c key_words -r 'port 80'

