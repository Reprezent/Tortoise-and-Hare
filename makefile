
tnh: TnH.c
	gcc -Wall -O3 -Ofast -std=c11 -o $@ $< -lcrypto

.PHONY: clean
clean:
	rm -f tnh
