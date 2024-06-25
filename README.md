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
docker run --name node-openssl-rest -p 8443:8443 -p 8080:8080 -it lspiehler/node-openssl-rest:latest
```