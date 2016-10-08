all:
	gcc main.c -std=gnu99 -lpcap -o dashboot

clean:
	rm dashboot
