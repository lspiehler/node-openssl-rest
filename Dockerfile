#https://github.com/open-quantum-safe/oqs-demos/blob/main/openssl3/Dockerfile
# Multi-stage build: First the full builder image:

ARG INSTALLDIR_OPENSSL=/opt/openssl32
ARG INSTALLDIR_LIBOQS=/opt/liboqs

# liboqs build type variant; maximum portability of image:
ARG LIBOQS_BUILD_DEFINES="-DOQS_DIST_BUILD=ON"

# Define the degree of parallelism when building the image; leave the number away only if you know what you are doing
ARG MAKE_DEFINES="-j 8"

ARG SIG_ALG="dilithium3"

ARG BASE_IMAGE="node:lts-alpine3.20"

FROM ${BASE_IMAGE} as buildopenssl
ARG INSTALLDIR_OPENSSL
ARG INSTALLDIR_LIBOQS
ARG LIBOQS_BUILD_DEFINES
ARG MAKE_DEFINES
ARG SIG_ALG

LABEL version="1"
ENV DEBIAN_FRONTEND noninteractive

RUN apk update && apk upgrade

# Get all software packages required for builing openssl
RUN apk add build-base linux-headers \
            libtool automake autoconf \
            make \
            git wget

# get current openssl sources
RUN mkdir /optbuild && cd /optbuild && git clone --depth 1 --branch master https://github.com/openssl/openssl.git
#mkdir /optbuild && cd /optbuild && git clone --branch master https://github.com/openssl/openssl.git &&  cd /optbuild/openssl && git checkout db2ac4f

# build OpenSSL3
WORKDIR /optbuild/openssl
RUN LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR_OPENSSL}/lib64" ./config enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-des enable-dsa enable-rc4 enable-dh shared --prefix=${INSTALLDIR_OPENSSL} && \
    make ${MAKE_DEFINES} && make install && if [ -d ${INSTALLDIR_OPENSSL}/lib64 ]; then ln -s ${INSTALLDIR_OPENSSL}/lib64 ${INSTALLDIR_OPENSSL}/lib; fi && if [ -d ${INSTALLDIR_OPENSSL}/lib ]; then ln -s ${INSTALLDIR_OPENSSL}/lib ${INSTALLDIR_OPENSSL}/lib64; fi

FROM ${BASE_IMAGE} as buildliboqs
# Take in all global args
ARG INSTALLDIR_OPENSSL
ARG INSTALLDIR_LIBOQS
ARG LIBOQS_BUILD_DEFINES
ARG MAKE_DEFINES
ARG SIG_ALG

LABEL version="1"
ENV DEBIAN_FRONTEND noninteractive

# Get all software packages required for builing liboqs:
RUN apk add build-base linux-headers \
            libtool automake autoconf cmake ninja \
            make \
            git wget

# Get OpenSSL image (from cache)
COPY --from=buildopenssl ${INSTALLDIR_OPENSSL} ${INSTALLDIR_OPENSSL}

RUN mkdir /optbuild && cd /optbuild && git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs

WORKDIR /optbuild/liboqs
RUN mkdir build && cd build && cmake -G"Ninja" .. -DOQS_ALGS_ENABLED=All -DOPENSSL_ROOT_DIR=${INSTALLDIR_OPENSSL} ${LIBOQS_BUILD_DEFINES} -DCMAKE_INSTALL_PREFIX=${INSTALLDIR_LIBOQS} && ninja install

FROM ${BASE_IMAGE} as buildoqsprovider
# Take in all global args
ARG INSTALLDIR_OPENSSL
ARG INSTALLDIR_LIBOQS
ARG LIBOQS_BUILD_DEFINES
ARG MAKE_DEFINES
ARG SIG_ALG

LABEL version="1"
ENV DEBIAN_FRONTEND noninteractive

# Get all software packages required for builing oqsprovider
RUN apk add build-base linux-headers \
            libtool cmake ninja \
            git wget

RUN mkdir /optbuild && cd /optbuild && git clone --depth 1 --branch main https://github.com/open-quantum-safe/oqs-provider.git

# Get openssl32 and liboqs
COPY --from=buildopenssl ${INSTALLDIR_OPENSSL} ${INSTALLDIR_OPENSSL}
COPY --from=buildliboqs ${INSTALLDIR_LIBOQS} ${INSTALLDIR_LIBOQS}

# build & install provider (and activate by default)
WORKDIR /optbuild/oqs-provider
RUN liboqs_DIR=${INSTALLDIR_LIBOQS} cmake -DOQS_ALGS_ENABLED=All -DOPENSSL_ROOT_DIR=${INSTALLDIR_OPENSSL} -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=${INSTALLDIR_OPENSSL} -S . -B _build && cmake --build _build  && cmake --install _build && cp _build/lib/oqsprovider.so ${INSTALLDIR_OPENSSL}/lib64/ossl-modules && sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf && sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf && sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf && sed -i "s/HOME\t\t\t= ./HOME           = .\nDEFAULT_GROUPS = kyber768/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf

WORKDIR ${INSTALLDIR_OPENSSL}/bin
# set path to use 'new' openssl. Dyn libs have been properly linked in to match
ENV PATH="${INSTALLDIR_OPENSSL}/bin:${PATH}"

ARG CACHE_DATE=2024-08-11-v7

# update config to allow unsafe renegotiation
RUN sed -i '/\[system_default_sect\]/a Options = UnsafeLegacyRenegotiation' /opt/openssl32/ssl/openssl.cnf

LABEL maintainer="Lyas Spiehler"

RUN apk add --update openssl git && \
    rm -rf /var/cache/apk/*

WORKDIR /var/node

RUN git clone https://github.com/lspiehler/node-openssl-rest.git

WORKDIR /var/node/node-openssl-rest

VOLUME /var/node/node-openssl-rest/ca

RUN npm install

EXPOSE 8443

EXPOSE 8080

CMD ["node", "index.js"]
