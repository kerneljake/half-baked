DESTDIR=/usr/local/bin
# change these to the tcp ports you want to shield
BLOCKED_PORTS=80,443

halfbaked: halfbaked.c
	cc -DBLOCKED_PORTS=\"${BLOCKED_PORTS}\" $< -o $@

install: halfbaked
	install halfbaked ${DESTDIR}

clean:
	rm -f *.core a.out *~

clobber: clean
	rm halfbaked
