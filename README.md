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

#### Run Docker Container
```
docker build -t lspiehler/node-openssl-rest:latest .
docker run -d --restart unless-stopped --name node-openssl-rest -p 8443:8443 -p 8080:8080 --env-file /var/node/node-openssl-rest/.env -v /var/docker/node-openssl-rest/certs:/var/node/node-openssl-rest/certs -v /cas:/var/node/node-openssl-rest/ca -it lspiehler/node-openssl-rest:latest
```

#### Update production container
```
docker stop node-openssl-rest
docker rm node-openssl-rest
docker image rm lspiehler/node-openssl-rest
docker run -d --restart unless-stopped --name node-openssl-rest -p 8443:8443 -p 8081:8081 --env-file /var/node/node-openssl-rest/.env -v /var/docker/node-openssl-rest/certs:/var/node/node-openssl-rest/certs -v /cas:/var/node/node-openssl-rest/ca -it lspiehler/node-openssl-rest:latest
```