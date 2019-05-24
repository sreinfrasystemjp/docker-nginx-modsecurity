################################
FROM ubuntu:18.04 as build
LABEL maintainer="https://sre-infra-system.jp/"

ENV DEBIAN_FRONTEND noninteractive
ENV MODSECURITY_VERSION v3.0.3
ENV MODSECURITY_CRS_VERSION 3.1.0
ENV NGX_MODSECURITY_VERSION v1.0.0
ENV NGX_NJS_VERSION 0.3.2
ENV NGX_GEOIP2_VERSION 3.2
ENV NGX_NDK_VERSION 0.3.1rc1
ENV LUAJIT_VERSION 2.0.5
#ENV NGX_LUA_VERSION 0.10.15
ENV NGX_LUA_VERSION 0.10.13
ENV NGX_DYNAMIC_UPSTREAM_VERSION 0.1.6
ENV NGINX_VERSION 1.17.0


# apt
RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends --no-install-suggests \
      ca-certificates      \
      autoconf             \
      automake             \
      build-essential      \
      git                  \
      libtool              \
      mercurial            \
      openssl              \
      pkgconf              \
      software-properties-common \
      wget                 \
      libcurl4-openssl-dev \
      libfuzzy-dev         \
      libgeoip-dev         \
      liblua5.1-dev        \
      libpcre3-dev         \
      libpcre++-dev        \
      libssl-dev           \
      libtool              \
      libyajl-dev          \
      libxml2-dev          \
      zlib1g-dev           \
      && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# apt for ngx_http_geoip2_module
RUN add-apt-repository ppa:maxmind/ppa && \
    apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends --no-install-suggests \
      libmaxminddb0        \
      libmaxminddb-dev     \
      mmdb-bin         &&  \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ModSecurity
RUN cd /opt && \
    git clone -b v3/master https://github.com/SpiderLabs/ModSecurity && \
    cd ModSecurity && \
    git checkout -b "${MODSECURITY_VERSION}" refs/tags/"${MODSECURITY_VERSION}" && \
    git submodule init && \
    git submodule update && \
    ./build.sh && \
    ./configure && \
    make && \
    make install
RUN strip /usr/local/modsecurity/bin/* /usr/local/modsecurity/lib/*.a /usr/local/modsecurity/lib/*.so*

# ModSecurity-nginx
RUN cd /opt && \
    wget -q https://github.com/SpiderLabs/ModSecurity-nginx/releases/download/${NGX_MODSECURITY_VERSION}/modsecurity-nginx-${NGX_MODSECURITY_VERSION}.tar.gz && \
    tar xzf modsecurity-nginx-${NGX_MODSECURITY_VERSION}.tar.gz && \
    rm -f modsecurity-nginx-${NGX_MODSECURITY_VERSION}.tar.gz

# owasp-modsecurity-crs
RUN cd /opt && \
    wget -q -O owasp-modsecurity-crs-${MODSECURITY_CRS_VERSION}.tar.gz https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/v${MODSECURITY_CRS_VERSION}.tar.gz && \
    tar xzf owasp-modsecurity-crs-${MODSECURITY_CRS_VERSION}.tar.gz && \
    rm -f owasp-modsecurity-crs-${MODSECURITY_CRS_VERSION}.tar.gz && \
    ln -s owasp-modsecurity-crs-${MODSECURITY_CRS_VERSION} owasp-modsecurity-crs

# njs
RUN cd /opt && \
    hg clone http://hg.nginx.org/njs && \
    cd /opt/njs && \
    hg up

# geoip2
RUN mkdir -p /opt/geoip2 && \
    cd /opt/geoip2 && \
    wget -q https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz && \
    tar xzf GeoLite2-Country.tar.gz && \
    rm -f GeoLite2-Country.tar.gz && \
    ls -al && \
    ln -s GeoLite2-Country_*/GeoLite2-Country.mmdb

# ngx_http_geoip2_module
RUN cd /opt && \
    wget -q -O ngx_http_geoip2_module-${NGX_GEOIP2_VERSION}.tar.gz https://github.com/leev/ngx_http_geoip2_module/archive/${NGX_GEOIP2_VERSION}.tar.gz && \
    tar xzf ngx_http_geoip2_module-${NGX_GEOIP2_VERSION}.tar.gz && \
    rm -f ngx_http_geoip2_module-${NGX_GEOIP2_VERSION}.tar.gz

# ngx_devel_kit
RUN cd /opt && \
    wget -q -O ngx_devel_kit-${NGX_NDK_VERSION}.tar.gz https://github.com/simplresty/ngx_devel_kit/archive/v${NGX_NDK_VERSION}.tar.gz && \
    tar xzf ngx_devel_kit-${NGX_NDK_VERSION}.tar.gz && \
    rm -f ngx_devel_kit-${NGX_NDK_VERSION}.tar.gz

# luajit2
RUN cd /opt && \
    wget -q -O luajit2-${LUAJIT_VERSION}.tar.gz https://github.com/openresty/luajit2/archive/v${LUAJIT_VERSION}.tar.gz && \
    tar xzf luajit2-${LUAJIT_VERSION}.tar.gz && \
    rm -f luajit2-${LUAJIT_VERSION}.tar.gz
RUN cd /opt && \
    cd /opt/luajit2-${LUAJIT_VERSION} && \
    make && \
    make install "PREFIX=/opt/luajit2"

# lua-nginx-module
RUN cd /opt && \
    wget -q -O lua-nginx-module-${NGX_LUA_VERSION}.tar.gz https://github.com/openresty/lua-nginx-module/archive/v${NGX_LUA_VERSION}.tar.gz && \
    tar xzf lua-nginx-module-${NGX_LUA_VERSION}.tar.gz && \
    rm -f lua-nginx-module-${NGX_LUA_VERSION}.tar.gz

# ngx_dynamic_upstream
RUN cd /opt && \
    wget -q -O ngx_dynamic_upstream-${NGX_DYNAMIC_UPSTREAM_VERSION}.tar.gz https://github.com/cubicdaiya/ngx_dynamic_upstream/archive/v${NGX_DYNAMIC_UPSTREAM_VERSION}.tar.gz && \
    tar xzf ngx_dynamic_upstream-${NGX_DYNAMIC_UPSTREAM_VERSION}.tar.gz && \
    rm -f ngx_dynamic_upstream-${NGX_DYNAMIC_UPSTREAM_VERSION}.tar.gz

# nginx
RUN cd /opt && \
    wget -q https://nginx.org/download/nginx-"$NGINX_VERSION".tar.gz && \
    tar xzf nginx-"$NGINX_VERSION".tar.gz
RUN cd /opt/nginx-"$NGINX_VERSION" && \
    export LUAJIT_LIB=/opt/luajit2/lib && \
    export LUAJIT_INC=/opt/luajit2/include/luajit-2.0 && \
    ./configure \
      --prefix=/usr/local/nginx \
      --sbin-path=/usr/local/nginx/nginx \
      --modules-path=/usr/local/nginx/modules \
      --conf-path=/etc/nginx/nginx.conf \
      --error-log-path=/var/log/nginx/error.log \
      --http-log-path=/var/log/nginx/access.log \
      --pid-path=/run/nginx.pid \
      --lock-path=/var/lock/nginx.lock \
      --user=www-data \
      --group=www-data \
      --with-pcre-jit \
      --with-file-aio \
      --with-threads \
      --with-http_addition_module \
      --with-http_auth_request_module \
      --with-http_flv_module \
      --with-http_gunzip_module \
      --with-http_gzip_static_module \
      --with-http_mp4_module \
      --with-http_random_index_module \
      --with-http_realip_module \
      --with-http_slice_module \
      --with-http_ssl_module \
      --with-http_sub_module \
      --with-http_stub_status_module \
      --with-http_v2_module \
      --with-http_secure_link_module \
      --with-stream \
      --with-stream_realip_module \
      --with-cc-opt='-g -O2 -specs=/usr/share/dpkg/no-pie-compile.specs -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
      --with-ld-opt='-specs=/usr/share/dpkg/no-pie-link.specs -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie -Wl,-rpath,$LUAJIT_LIB' \
      --with-http_dav_module \
      --add-dynamic-module=/opt/modsecurity-nginx-${NGX_MODSECURITY_VERSION} \
      --add-dynamic-module=/opt/njs/nginx \
      --add-dynamic-module=/opt/ngx_http_geoip2_module-${NGX_GEOIP2_VERSION} \
      --add-dynamic-module=/opt/ngx_devel_kit-${NGX_NDK_VERSION} \
      --add-dynamic-module=/opt/lua-nginx-module-${NGX_LUA_VERSION} \
      --add-dynamic-module=/opt/ngx_dynamic_upstream-${NGX_DYNAMIC_UPSTREAM_VERSION} \
    && \
    make && \
    make install && \
    make modules

RUN mkdir -p /var/log/nginx/ && \
    touch /var/log/nginx/access.log && \
    touch /var/log/nginx/error.log && \
    touch /var/log/nginx/modsec_audit.log

EXPOSE 80
STOPSIGNAL SIGTERM
CMD ["/usr/local/nginx/nginx", "-g", "daemon off;"]


################################
FROM ubuntu:18.04
LABEL maintainer="https://sre-infra-system.jp/"

ENV DEBIAN_FRONTEND noninteractive

# apt
RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends --no-install-suggests \
      ca-certificates      \
      curl                 \
      git                  \
      less                 \
      software-properties-common \
      tzdata               \
      vim                  \
      wget                 \
      libcurl4-openssl-dev \
      libfuzzy2            \
      libgeoip1            \
      liblua5.1-0          \
      libyajl2             \
      libxml2              \
      lua5.1               \
      && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# apt for ngx_http_geoip2_module
RUN add-apt-repository ppa:maxmind/ppa && \
    apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends --no-install-suggests \
      libmaxminddb0        \
      libmaxminddb-dev     \
      mmdb-bin         &&  \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# user
RUN groupadd -g 101 nginx && \
    useradd -d /nonexistent -s /bin/false -u 101 -g 101 nginx

# ModSecurity
COPY --from=build /usr/local/modsecurity /usr/local/modsecurity

# luajit2
COPY --from=build /opt/luajit2 /opt/luajit2
COPY ld.so.conf.d/luajit2.conf /etc/ld.so.conf.d/luajit2.conf
RUN ldconfig

# geoip2
COPY --from=build /opt/geoip2 /opt/geoip2

# nginx
COPY --from=build /usr/local/nginx /usr/local/nginx
COPY --from=build /etc/nginx /etc/nginx
COPY conf /etc/nginx/conf
COPY conf.d /etc/nginx/conf.d
RUN cd /etc/nginx && \
    rm -f nginx.conf && \
    ln -s conf/nginx.conf && \
    mkdir -p /var/log/nginx/ && \
    touch /var/log/nginx/access.log && \
    touch /var/log/nginx/error.log && \
    touch /var/log/nginx/modsec_audit.log

# ModSecurity-nginx
COPY modsecurity.d /opt/modsecurity.d

# owasp-modsecurity-crs
RUN mkdir -p /etc/owasp-modsecurity-crs
COPY --from=build /opt/owasp-modsecurity-crs/crs-setup.conf.example /opt/owasp-modsecurity-crs/crs-setup.conf
COPY --from=build /opt/owasp-modsecurity-crs/rules /opt/owasp-modsecurity-crs/rules
RUN cd /opt/owasp-modsecurity-crs/rules && \
    mv REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf && \
    mv RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

EXPOSE 80
EXPOSE 443
STOPSIGNAL SIGTERM
CMD ["/usr/local/nginx/nginx", "-g", "daemon off;"]
