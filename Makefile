
all: main

hex.o: hex.c hex.h
	gcc -c $<

aes.o: aes.c aes.h
	gcc -c $<

main: main.c aes.o hex.o
	gcc $^ -o $@
