FROM node:lts-alpine3.20

LABEL maintainer="Lyas Spiehler"

RUN apk add --update openssl git && \
    rm -rf /var/cache/apk/*

WORKDIR /var/node

RUN git clone https://github.com/lspiehler/node-openssl-rest.git

WORKDIR /var/node/node-openssl-rest

VOLUME /var/node/node-openssl-rest/ca

RUN npm install

RUN npm install bower -g

#RUN bower install --allow-root tempusdominus-bootstrap-3 bootstrap@3 jquery-ui moment

EXPOSE 8443

EXPOSE 8080

CMD ["node", "index.js"]
