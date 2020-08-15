LDLIBS=-lpcap
LIBS = -lpthread

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) $(LIBS) -o $@

clean:
	rm -f send-arp-test *.o
