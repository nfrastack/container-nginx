# SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
#
# SPDX-License-Identifier: MIT

ARG BASE_IMAGE
ARG DISTRO
ARG DISTRO_VARIANT

FROM ${BASE_IMAGE}:${DISTRO}_${DISTRO_VARIANT}

LABEL \
        org.opencontainers.image.title="Nginx" \
        org.opencontainers.image.description="Web server" \
        org.opencontainers.image.url="https://hub.docker.com/r/nfrastack/nginx" \
        org.opencontainers.image.documentation="https://github.com/nfrastack/container-nginx/blob/main/README.md" \
        org.opencontainers.image.source="https://github.com/nfrastack/container-nginx.git" \
        org.opencontainers.image.authors="Nfrastack <code@nfrastack.com>" \
        org.opencontainers.image.vendor="Nfrastack <https://www.nfrastack.com>" \
        org.opencontainers.image.licenses="MIT"

ARG \
        NGINX_VERSION="release-1.29.1" \
        NGINX_REPO_URL="https://github.com/nginx/nginx" \
        NGINX_MODULE_AUTH_LDAP_VERSION="241200eac8e4acae74d353291bd27f79e5ca3dc4" \
        NGINX_MODULE_BROTLI_VERSION="a71f9312c2deb28875acc7bacfdd5695a111aa53" \
        NGINX_MODULE_COOKIE_FLAG_VERSION="c4ff449318474fbbb4ba5f40cb67ccd54dc595d4" \
        NGINX_MODULE_MORE_HEADERS_VERSION="201e7446b6aff930188d3d1863af4ad829fc6b21" \
        NGINX_MODULE_BLOCK_BOTS_VERSION="V4.2025.09.5442"

ENV \
    NGINX_USER=nginx \
    NGINX_GROUP=www-data \
    NGINX_WEBROOT=/www/html \
    CONTAINER_ENABLE_SCHEDULING=TRUE \
    IMAGE_NAME="nfrastack/nginx" \
    IMAGE_REPO_URL="https://github.com/nfrastack/container-nginx/"

COPY CHANGELOG.md /usr/src/container/CHANGELOG.md
COPY LICENSE /usr/src/container/LICENSE
COPY README.md /usr/src/container/README.md

RUN echo "" && \
    case "$(cat /etc/os-release | grep VERSION_ID | cut -d = -f 2 | cut -d . -f 1,2 | cut -d _ -f 1)" in \
        3.[5-9] | 3.1[0-6] ) alpine_ssl=libressl ;; \
        3.1[7-9]* | 3.2[0-9] ) alpine_ssl=openssl ;; \
        *) : ;; \
    esac ; \
    NGINX_BUILD_DEPS_ALPINE=" \
                                gcc \
                                gd-dev \
                                geoip-dev \
                                libc-dev \
                                ${alpine_ssl}-dev \
                                libxslt-dev \
                                linux-headers \
                                make \
                                pcre-dev \
                                perl-dev \
                                tar \
                                zlib-dev \
                            " \
                            && \
    BROTLI_BUILD_DEPS_ALPINE=" \
                                autoconf \
                                automake \
                                cmake \
                                g++ \
                                libtool \
                            " \
                            && \
    AUTH_LDAP_BUILD_DEPS_ALPINE=" \
                                openldap-dev \
                                " \
                                && \
    AUTH_LDAP_BUILD_DEPS_DEBIAN=" \
                                libldap2-dev \
                                " \
                                && \
    BROTLI_BUILD_DEPS_DEBIAN=" \
                                make \
                             " \
                             && \
    NGINX_BUILD_DEPS_DEBIAN=" \
                                build-essential \
                                git \
                                libgd-dev \
                                libgeoip-dev \
                                libpcre2-dev \
                                libperl-dev \
                                libssl-dev \
                                libxml2-dev \
                                libxslt1-dev \
                                zlib1g-dev \
                            " \
                            && \
    NGINX_RUN_DEPS_DEBIAN=" \
                                geoip-bin \
                                git \
                                inotify-tools \
                                libgd3 \
                                libgeoip1 \
                                libpcre2 \
                                libxml2 \
                                libxslt1.1 \
                                openssl \
                                perl \
                                software-properties-common \
                                zlib1g \
                            " \
                            && \
    source /container/base/functions/container/build && \
    container_build_log && \
    sed -i "/www-data/d" /etc/group* && \
    create_user "${NGINX_USER}" 80 "${NGINX_GROUP}" 82 /var/cache/nginx && \
    package update && \
    package upgrade && \
    package install \
                    AUTH_LDAP_BUILD_DEPS \
                    NGINX_BUILD_DEPS \
                    BROTLI_BUILD_DEPS \
                    && \
    mkdir -p \
                /www \
                /var/log/nginx \
                && \
    chown -R "${NGINX_USER}":"${NGINX_GROUP}" /var/log/nginx && \
    clone_git_repo https://github.com/kvspb/nginx-auth-ldap ${NGINX_MODULE_AUTH_LDAP_VERSION} && \
    clone_git_repo https://github.com/google/ngx_brotli ${NGINX_MODULE_BROTLI_VERSION} && \
    clone_git_repo https://github.com/AirisX/nginx_cookie_flag_module ${NGINX_MODULE_COOKIE_FLAG_VERSION} && \
    clone_git_repo https://github.com/openresty/headers-more-nginx-module ${NGINX_MODULE_MORE_HEADERS_VERSION} && \
    clone_git_repo https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker "${NGINX_MODULE_BLOCK_BOTS_VERSION}" && \
    clone_git_repo ${NGINX_REPO_URL} ${NGINX_VERSION} && \
    mv auto/configure . && \
    case "$(container_info_distro):$(container_info_distro_variant)" in \
        alpine-3.[5-9] ) : ;; \
        *) ccflag="-Wno-vla-parameter" ;; \
    esac ; \
    ./configure \
                --prefix=/etc/nginx \
                --sbin-path=/usr/sbin/nginx \
                --modules-path=/usr/lib/nginx/modules \
                --conf-path=/etc/nginx/nginx.conf \
                --error-log-path=/dev/null \
                --http-log-path=/dev/null \
                --pid-path=/var/run/nginx.pid \
                --lock-path=/var/run/nginx.lock \
                --http-client-body-temp-path=/var/cache/nginx/client_temp \
                --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
                --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
                --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
                --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
                --user=${NGINX_USER} \
                --group=${NGINX_GROUP} \
                --add-module=${GIT_REPO_SRC_NGINX_AUTH_LDAP} \
                --add-module=${GIT_REPO_SRC_NGX_BROTLI} \
                --add-module=${GIT_REPO_SRC_NGINX_COOKIE_FLAG_MODULE} \
                --add-module=${GIT_REPO_SRC_HEADERS_MORE_NGINX_MODULE} \
                --with-cc-opt='${cc_flag} -s' \
                --with-compat \
                --with-file-aio \
                --with-http_addition_module \
                --with-http_auth_request_module \
                --with-http_dav_module \
                --with-http_geoip_module=dynamic \
                --with-http_gunzip_module \
                --with-http_gzip_static_module \
                --with-http_image_filter_module=dynamic \
                --with-http_mp4_module \
                --with-http_perl_module=dynamic \
                --with-http_random_index_module \
                --with-http_realip_module \
                --with-http_secure_link_module \
                --with-http_slice_module \
                --with-http_ssl_module \
                --with-http_stub_status_module \
                --with-http_sub_module \
                --with-http_v2_module \
                --with-http_v3_module \
                --with-http_xslt_module=dynamic \
                --with-mail \
                --with-mail_ssl_module \
                --with-stream \
                --with-stream_geoip_module=dynamic \
                --with-stream_realip_module \
                --with-stream_ssl_module \
                --with-stream_ssl_preread_module \
                --with-threads \
                --without-http_memcached_module \
                && \
    make -j$(getconf _NPROCESSORS_ONLN) && \
    make install && \
    rm -rf \
            /etc/nginx/*.default \
            /etc/nginx/html/ \
            && \
    mkdir -p \
            /etc/nginx/sites.available \
            /etc/nginx/sites.enabled \
            /usr/share/nginx/html \
            && \
    mkdir -p /usr/share/nginx/html/ && \
    install -m644 html/index.html /usr/share/nginx/html/ && \
    install -m644 html/50x.html /usr/share/nginx/html/ && \
    ln -s ../../usr/lib/nginx/modules /etc/nginx/modules && \
    strip /usr/sbin/nginx* && \
    strip /usr/lib/nginx/modules/*.so && \
    \
    mkdir -p    \
                /etc/nginx/snippets/blockbots \
                /etc/nginx/snippets/blockbots-custom \
                && \
    cp -R \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/bad-referrer-words.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/blacklist-ips.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/blacklist-user-agents.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/blockbots.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/custom-bad-referrers.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/ddos.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/whitelist-domains.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/bots.d/whitelist-ips.conf \
                ${GIT_REPO_SRC_NGINX_ULTIMATE_BAD_BOT_BLOCKER}/conf.d/globalblacklist.conf \
            /etc/nginx/snippets/blockbots/ \
            && \
    sed -i \
                -e "s|/etc/nginx/bots.d/|/etc/nginx/snippets/blockbots/|g" \
                -e "s|/etc/nginx/snippets/blockbots/bad-referrer-words.conf|/etc/nginx/snippets/blockbots-custom/bad-referrer-words.conf|g" \
                -e "s|/etc/nginx/snippets/blockbots/blacklist-ips.conf|/etc/nginx/snippets/blockbots-custom/blacklist-ips.conf|g" \
                -e "s|/etc/nginx/snippets/blockbots/blacklist-user-agents.conf|/etc/nginx/snippets/blockbots-custom/blacklist-user-agents.conf|g" \
                -e "s|/etc/nginx/snippets/blockbots/whitelist-domains.conf|/etc/nginx/snippets/blockbots-custom/whitelist-domains.conf|g" \
                -e "s|/etc/nginx/snippets/blockbots/whitelist-ips.conf|/etc/nginx/snippets/blockbots-custom/whitelist-ips.conf|g" \
            /etc/nginx/snippets/blockbots/globalblacklist.conf && \
    \
    echo "include /etc/nginx/snippets/fastcgi_params[.]custom;" >> /etc/nginx/fastcgi_params && \
    \
    COMPILE_RUN_DEPS_ALPINE="$( \
                                scanelf --needed --nobanner /usr/sbin/nginx /usr/lib/nginx/modules/*.so /tmp/envsubst \
                                  | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
                                  | sort -u \
                                  | xargs -r package info --installed \
                                  | sort -u \
                                )" && \
    \
    NGINX_RUN_DEPS_ALPINE="     \
                                ${COMPILE_RUN_DEPS_ALPINE} \
                                apache2-utils \
                                inotify-tools \
                                libldap \
                                pcre \
                           " \
                           && \
    \
    package install \
                    NGINX_RUN_DEPS \
                    && \
    \
    package remove \
                    AUTH_LDAP_BUILD_DEPS \
                    BROTLI_BUILD_DEPS \
                    NGINX_BUILD_DEPS \
                    && \
    package cleanup

COPY rootfs /
