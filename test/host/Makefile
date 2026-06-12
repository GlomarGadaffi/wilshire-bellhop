CFLAGS = -Wall -Wextra -O2 -g -I../../include -fsanitize=address,undefined
harness: harness.c ../../src/littlessh.c
	$(CC) $(CFLAGS) -o $@ $^ -lmbedcrypto
clean:
	rm -f harness
