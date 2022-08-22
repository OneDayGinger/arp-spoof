LDLIBS=-lpcap

all: send-arp

main.o: ./gilgil_lib/mac.h ./gilgil_lib/ip.h ./gilgil_lib/ethhdr.h ./gilgil_lib/arphdr.h arpspoof.h main.cpp

arpspoof.o: ./gilgil_lib/mac.h ./gilgil_lib/ip.h ./gilgil_lib/ethhdr.h ./gilgil_lib/arphdr.h arpspoof.h arpspoof.cpp

arphdr.o: ./gilgil_lib/mac.h ./gilgil_lib/ip.h ./gilgil_lib/arphdr.h ./gilgil_lib/arphdr.cpp

ethhdr.o: ./gilgil_lib/mac.h ./gilgil_lib/ethhdr.h ./gilgil_lib/ethhdr.cpp

ip.o: ./gilgil_lib/ip.h ./gilgil_lib/ip.cpp

mac.o: ./gilgil_lib/mac.h ./gilgil_lib/mac.cpp

send-arp: main.o arpspoof.o ./gilgil_lib/arphdr.o ./gilgil_lib/ethhdr.o ./gilgil_lib/ip.o ./gilgil_lib/mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o ./gilgil_lib/*.o