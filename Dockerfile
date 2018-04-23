FROM ubuntu:latest
MAINTAINER Lyas Spiehler

RUN apt -y update

RUN apt install -y openssl git curl

RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -

RUN apt install -y nodejs

WORKDIR /root

RUN git clone https://github.com/lspiehler/node-openssl-rest.git

WORKDIR /root/node-openssl-rest

RUN npm install

EXPOSE 8443

CMD ["node", "index.js"]