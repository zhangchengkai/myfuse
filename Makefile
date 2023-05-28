.PHONY: all
all:
	gcc -Wall myfs.c `pkg-config fuse3 --cflags --libs` -o myfs
.PHONY: run
run:
	./myfs test_cuse
.PHONY: clean
clean:
	umount -l ./test_cuse
	rm myfs
