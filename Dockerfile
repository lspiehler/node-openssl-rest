FROM ubuntu:16.04
MAINTAINER Lyas Spiehler

RUN apt -y update

RUN apt install -y openssl git curl

RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -

RUN apt install -y nodejs

WORKDIR /root

RUN git clone https://github.com/lspiehler/node-openssl-rest.git

WORKDIR /root/node-openssl-rest

RUN npm install

RUN npm install bower -g

RUN bower install eonasdan-bootstrap-datetimepicker#latest bootstrap@3 jquery-ui

EXPOSE 8443

CMD ["node", "index.js"]
