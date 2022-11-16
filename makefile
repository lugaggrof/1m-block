all : 1m-block

1m-block: 1m-block.o
	g++ -o 1m-block 1m-block.o -lnetfilter_queue

1m-block.o:
	g++ -c -o 1m-block.o main.cpp -lnetfilter_queue

clean:
	rm -f 1m-block
	rm -f *.o
