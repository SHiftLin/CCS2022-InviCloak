PWD = $(shell pwd)

.PHONY: all dep invicloak static
all:
	cd mod && ./make.sh
	cd invicloak/nginx_mod/ && ln -sf $(PWD)/static ./
	cd invicloak/nginx_mod/conf && ln -sf $(PWD)/cert ./
	cd invicloak/nginx_mod/conf && cp -f $(PWD)/nginx.conf ./

dep: invicloak static

invicloak:
	mkdir -p invicloak
	cd invicloak && wget -nc https://nginx.org/download/nginx-1.17.8.tar.gz
	cd invicloak && tar -zxf nginx-1.17.8.tar.gz
	cd invicloak && wget -nc https://www.openssl.org/source/openssl-1.1.1g.tar.gz
	cd invicloak && tar -zxf openssl-1.1.1g.tar.gz
	cd invicloak/nginx-1.17.8 && \
	./configure --with-http_ssl_module --with-openssl=../openssl-1.1.1g --with-stream --add-module=../../mod --prefix=$(PWD)/invicloak/nginx_mod

static:
	cd static && if [ ! -e privacy ]; then \
        mkdir privacy && python3 genTextFiles.py privacy; fi
