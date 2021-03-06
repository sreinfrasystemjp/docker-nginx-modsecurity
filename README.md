# docker-nginx-modsecurity
docker nginx with modsecurity, njs, geoip2, lua, dynamic_upstream

## Usage

```
docker pull sreinfrasystemjp/docker-nginx-modsecurity
docker run --rm \
  -p 10080:80 \
  -v $(pwd)/log:/var/log/nginx \
  sreinfrasystemjp/docker-nginx-modsecurity
curl http://localhost:10080/
```

## Functions

|target|function|note|
|---|---|---|
|PCIDSS 6.6 WAF|nginx modsecurity v3 + crs||
|GDPR mask ip address|nginx njs|https://www.nginx.com/blog/data-masking-user-privacy-nginscript/ |
|Get country code before mask ip address|nginx geoip2||
|Get distributed unique ID|nginx lua ( and [katsubushi](https://github.com/kayac/go-katsubushi) )|https://speakerdeck.com/fujiwara3/katsubushi?slide=56 |
|Blue-Green Deployment|nginx dynamic_upstream|https://qiita.com/cubicdaiya/items/09023ca6ed056d3d1ed2 |


## Library's Version

|production|version|url|note|
|---|---|---|---|
|ubuntu|18.04|https://hub.docker.com/_/ubuntu/ |docker image|
|nginx|1.17.0|http://nginx.org/en/download.html ||
|nginx/njs|0.3.2|https://github.com/nginx/njs/ ||
|SpiderLabs/ModSecurity|3.0.3|https://github.com/SpiderLabs/ModSecurity/ ||
|SpiderLabs/ModSecurity-nginx|1.0.0|https://github.com/SpiderLabs/ModSecurity-nginx/ ||
|SpiderLabs/owasp-modsecurity-crs|3.1.0|https://github.com/SpiderLabs/owasp-modsecurity-crs/ ||
|libmaxminddb|1.3.2-0+maxmind1~artful|https://launchpad.net/~maxmind/+archive/ubuntu/ppa?field.series_filter=bionic ||
|leev/ngx_http_geoip2_module|3.2|https://github.com/leev/ngx_http_geoip2_module/ ||
|MaxMind GeoLite2 data|20190521|https://dev.maxmind.com/geoip/geoip2/geolite2/ ||
|simplresty/ngx_devel_kit|0.3.1rc1|https://github.com/simplresty/ngx_devel_kit/ ||
|openresty/luajit2|2.0.5|https://github.com/openresty/luajit2/ ||
|openresty/lua-nginx-module|0.10.13|https://github.com/openresty/lua-nginx-module/ ||
|cubicdaiya/ngx_dynamic_upstream|0.1.6|https://github.com/cubicdaiya/ngx_dynamic_upstream ||

## nginx with modsecurity

```
git clone https://github.com/sreinfrasystemjp/docker-nginx-modsecurity.git
cd docker-nginx-modsecurity

docker run --rm \
  -p 10080:80 \
  -v $(pwd)/log:/var/log/nginx \
  sreinfrasystemjp/docker-nginx-modsecurity

# 200 OK
curl http://localhost:10080/
# 403 Forbidden
curl http://localhost:10080/?f=../../etc

tail log/access.log
tail log/error.log
tail log/modsec_audit.log
```


## nginx with modsecurity, njs, geoip2, lua

```
git clone https://github.com/sreinfrasystemjp/docker-nginx-modsecurity.git
cd docker-nginx-modsecurity
```

* log_format : see [conf.d.mask_ip.geoip2.lua.dynamic_upstream/default.conf](https://github.com/sreinfrasystemjp/conf.d.mask_ip.geoip2.lua.dynamic_upstream/default.conf)
    ```
    log_format  masked
        '$request_id $remote_addr_masked '
        '$geoip2_country_code $geoip2_country_name $upstream_addr ...';
    log_format  nomask
        '$request_id $remote_addr_masked  $remote_addr';

    access_log  /var/log/nginx/access.log  masked;
    access_log  /var/log/nginx/access.nomask.log  nomask;
    ```

```
docker run --rm \
  -p 10080:80 \
  -v $(pwd)/log:/var/log/nginx \
  -v $(pwd)/conf.d.mask_ip.geoip2.lua.dynamic_upstream:/etc/nginx/conf.d \
  sreinfrasystemjp/docker-nginx-modsecurity

# njs : $remote_addr_masked : https://www.nginx.com/blog/data-masking-user-privacy-nginscript/
# geoip2: $geoip2_country_code $geoip2_country_name
# lua: /lua
curl http://localhost:10080/lua
tail log/access.log
tail log/access.nomask.log
```


## nginx with self certificate authority

```
docker run --rm \
  -p 10080:80 \
  -p 10443:443 \
  -v $(pwd)/log:/var/log/nginx \
  sreinfrasystemjp/docker-nginx-modsecurity

# download ca.der
curl -O http://localhost:10080/ca.der

# install ca.der into your browser

# edit your /etc/hosts
127.0.0.1       localhost nginx.docker.test nginx.example.com nginx.example.jp

# browser access
https://localhost:10443/
https://nginx.docker.test:10443/
https://nginx.example.com:10443/
https://nginx.example.jp:10443/
```

### self certificate authority

|role|Subject|Date|
|---|---|---|
|self CA|C=JP/ST=Earth/L=Japan/O=localhost/CN=localhost|2019-04-03 - 2039-03-29|
|server|C=JP/ST=Asia/L=Japan/O=localhost/CN=localhost|2019-04-03 - 2029-03-31|

* server's SAN

    ```
    localhost
    docker.test
    *.docker.test
    example.com
    *.example.com
    example.jp
    *.example.jp
    ```

### nginx SSL Certificate

|nginx setting|file|note|
|---|---|---|
|ssl_certificate|conf/nginx.crt|self CA crt + server crt|
|ssl_certificate_key|conf/server.key|server key|

### install ca.der into your browser

download ca.der
from

https://github.com/sreinfrasystemjp/docker-nginx-modsecurity/blob/master/conf/ca.der

or

http://localhost:10080/ca.der

and install ca.der into your browser

* chrome
    * jp : https://jp.globalsign.com/support/faq/558.html

* firefox
    * jp : https://jp.globalsign.com/support/faq/559.html


## nginx with dynamic_upstream

```
docker run --rm \
  --name nginx_dynamic \
  -p 10080:80 \
  -p 10081:81 \
  -p 10082:82 \
  -p 10443:443 \
  -v $(pwd)/log:/var/log/nginx \
  sreinfrasystemjp/docker-nginx-modsecurity

# download ca.der
curl -O http://localhost:10080/ca.der

# install ca.der into your browser

# edit your /etc/hosts
127.0.0.1       localhost dynamic.docker.test

# browser direct access (blue)
http://dynamic.docker.test:10081/
# browser direct access (green)
http://dynamic.docker.test:10082/

# browser access (blue)
https://dynamic.docker.test:10443/

# change blue(127.0.0.1:81) -> green(127.0.0.1:82)
docker exec -it nginx_dynamic /bin/bash
    curl "http://127.0.0.1/dynamic?upstream=zoneapp"

    curl "http://127.0.0.1/dynamic?upstream=zoneapp&server=127.0.0.1:82&up="
    curl "http://127.0.0.1/dynamic?upstream=zoneapp&server=127.0.0.1:81&down="
    cd /etc/nginx/conf
    ln -sf upstream.app.green.conf upstream.app.conf
    ls -al upstream.app.*

    curl "http://127.0.0.1/dynamic?upstream=zoneapp"

# browser access (green)
https://dynamic.docker.test:10443/

# check log $upstream_addr
tail log/access.log
```


## Licence

Apache License 2.0

This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com)

* Library's License

|production|license|license url|note|
|---|---|---|---|
|docker|Apache-2.0|https://github.com/moby/moby/blob/master/LICENSE ||
|ubuntu|GPL,etc|https://www.ubuntu.com/licensing ||
|nginx|BSD like|https://github.com/nginx/nginx/blob/master/docs/text/LICENSE ||
|nginx/njs|BSD like|https://github.com/nginx/njs/blob/master/LICENSE ||
|SpiderLabs/ModSecurity|Apache-2.0|https://github.com/SpiderLabs/ModSecurity/blob/v3/master/LICENSE ||
|SpiderLabs/ModSecurity-nginx|Apache-2.0|https://github.com/SpiderLabs/ModSecurity-nginx/blob/master/LICENSE ||
|SpiderLabs/owasp-modsecurity-crs|Apache-2.0|https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/master/LICENSE ||
|libmaxminddb|Apache-2.0|https://github.com/maxmind/libmaxminddb/blob/master/LICENSE ||
|leev/ngx_http_geoip2_module|BSD 2-Clause|https://github.com/leev/ngx_http_geoip2_module/blob/master/LICENSE ||
|MaxMind GeoLite2 data|CC BY-SA 4.0|https://dev.maxmind.com/geoip/geoip2/geolite2/ ||
|simplresty/ngx_devel_kit|BSD 3-Clause|https://github.com/simplresty/ngx_devel_kit/blob/master/LICENSE ||
|openresty/luajit2|MIT,etc|https://github.com/openresty/luajit2/blob/v2.1-agentzh/COPYRIGHT ||
|openresty/lua-nginx-module|BSD|https://github.com/openresty/lua-nginx-module#copyright-and-license ||
|cubicdaiya/ngx_dynamic_upstream|BSD like|https://github.com/cubicdaiya/ngx_dynamic_upstream/blob/master/LICENSE ||

## Author

[ihironao](https://github.com/ihironao)
