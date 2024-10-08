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
docker build -t lspiehler/node-openssl-rest:63578a9 .
docker run -d --restart unless-stopped --name node-openssl-rest --add-host opensearch.certificatetools.com:192.168.1.49 -p 8443:8443 -p 8080:8080 --env-file /var/node/node-openssl-rest/.env -v /var/docker/node-openssl-rest/certs:/var/node/node-openssl-rest/certs -v /cas:/var/node/node-openssl-rest/ca -it lspiehler/node-openssl-rest:63578a9
docker push lspiehler/node-openssl-rest:63578a9
```

#### Update production container
```
docker stop node-openssl-rest
docker rm node-openssl-rest
docker image rm lspiehler/node-openssl-rest
docker run -d --restart unless-stopped --name node-openssl-rest -p 8443:8443 -p 8081:8081 --env-file /var/node/node-openssl-rest/.env -v /var/docker/node-openssl-rest/certs:/var/node/node-openssl-rest/certs -v /cas:/var/node/node-openssl-rest/ca -it lspiehler/node-openssl-rest:63578a9
```