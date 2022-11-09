all : netfilter-test

netfilter-test: netfilter-test.o
	gcc -o netfilter-test netfilter-test.o -lnetfilter_queue

netfilter-test.o:
	gcc -c -o netfilter-test.o main.c -lnetfilter_queue

clean:
	rm -f netfilter-test
	rm -f *.o

