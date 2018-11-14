src=Util.cpp SnifferThread.cpp PacketHandler.cpp main.cpp

sniffer: $(src)
	g++ $(src) -o sniffer -g -O2 -lpcap -lpthread

clean:
	rm sniffer
