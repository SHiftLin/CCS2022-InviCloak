#!/bin/bash
cd invicloak/nginx_mod
./sbin/nginx -s quit > /dev/null 2>&1
./sbin/nginx
