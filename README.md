# node-openssl-rest

### Installation
```
git clone https://github.com/lspiehler/node-openssl-rest.git
cd node-openssl-rest
npm install
npm install -g bower
bower install --allow-root eonasdan-bootstrap-datetimepicker#latest bootstrap@3 jquery-ui
```

#### Windows
```
SET PUBLICHTTP=publicdomainname:port&&node index.js
```

#### Linux
```
export PUBLICHTTP=publicdomainname:port&&node index.js
```

#### Build, run and publish docker container
```
docker build -t ghcr.io/lspiehler/node-openssl-rest:latest .
docker run -it --rm --name node-openssl-rest --add-host opensearch.certificatetools.com:192.168.1.49 -p 8444:8443 -p 8081:8080 --env-file /var/node/node-openssl-rest/.env -v /var/docker/node-openssl-rest/certs:/var/node/node-openssl-rest/certs -v /cas:/var/node/node-openssl-rest/ca -it ghcr.io/lspiehler/node-openssl-rest:latest
docker push ghcr.io/lspiehler/node-openssl-rest:latest
```

#### Update production container
```
docker compose down
docker image rm ghcr.io/lspiehler/node-openssl-rest
docker compose up -d
```