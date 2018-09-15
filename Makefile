all: pcap_test

pcap_test: header.o main.o
	g++ -o pcap_test main.o header.o -lpcap

header.o: header.cpp header.h
	g++ -c -o header.o header.cpp

main.o: main.cpp header.h header.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -rf pcap_test *.o

