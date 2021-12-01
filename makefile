all:
	gcc -std=c99 cJSON.c cJsonTest.c -o main

clean:
	rm -rf main
