APXS = apxs2
CPPFLAGS =
LIBS =

SRCS = mod_ssl_preauth.c ldap.c

all: mod_ssl_preauth.la

mod_ssl_preauth.la: $(SRCS)
	$(APXS) -Wc,-Wall -Wc,-g -Wc,-O0 \
	-c $(SRCS) -lldap

install: mod_ssl_preauth.la
	$(APXS) -i -n ssl_preauth $^

clean:
	$(RM) *.o *.so *.a *.la *.lo *.slo
	$(RM) -rf .libs

debs:
	debuild -us -uc

.PHONY = all install mod_ssl_preauth
