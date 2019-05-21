FROM node:8-alpine

MAINTAINER Lyas Spiehler

RUN apk add --update openssl git && \
    rm -rf /var/cache/apk/*

WORKDIR /root

RUN git clone https://github.com/lspiehler/node-openssl-rest.git

WORKDIR /root/node-openssl-rest

VOLUME /root/node-openssl-rest/ca

RUN npm install

RUN npm install bower -g

RUN bower install --allow-root eonasdan-bootstrap-datetimepicker#latest bootstrap@3 jquery-ui

EXPOSE 8443

EXPOSE 8080

CMD ["node", "index.js"]
