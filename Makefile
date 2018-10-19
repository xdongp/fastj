main: 
	gcc fastjv1.c picohttpparser.c hash.c slog.c -o fastjv1 -lpcap -lrt -pthread -O3
clean:
	rm fastjv1 fastj -f
