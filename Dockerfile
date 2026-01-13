FROM node:lts-alpine3.23

LABEL maintainer="Lyas Spiehler"

RUN apk add --update python3 \
    openssl \
    git \
    dotnet8-runtime && \
    rm -rf /var/cache/apk/*

# update config to allow unsafe renegotiation
# RUN sed -i '/\[system_default_sect\]/a Options = UnsafeLegacyRenegotiation' /etc/ssl/openssl.cnf

#RUN sed -i '/\[openssl_init\]/a ssl_conf = ssl_sect' /etc/ssl/openssl.cnf && echo >> /etc/ssl/openssl.cnf && echo "[ssl_sect]" >> /etc/ssl/openssl.cnf && echo "system_default = system_default_sect" >> /etc/ssl/openssl.cnf && echo >> /etc/ssl/openssl.cnf && echo "[system_default_sect]" >> /etc/ssl/openssl.cnf  && echo "Options = UnsafeLegacyRenegotiation" >> /etc/ssl/openssl.cnf

LABEL maintainer="Lyas Spiehler"

WORKDIR /var/node

ARG CACHE_DATE=2026-01-13

RUN git clone https://github.com/lspiehler/node-openssl-rest.git

WORKDIR /var/node/node-openssl-rest

VOLUME /var/node/node-openssl-rest/ca

RUN npm install

EXPOSE 8443

EXPOSE 8080

CMD ["node", "index.js"]
