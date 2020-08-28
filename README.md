
## Setting up the EC2 Instance

```
sudo apt update
sudo apt install docker.io tmux python3-pip
sudo systemctl status docker
sudo systemctl unmask docker
sudo systemctl status docker
sudo systemctl start docker
pip3 install regex pymongo mongoengine ipython

```

## Example Commands

Run the docker honeypot with ports (2375, 2376, 2377, 4243, 4244), terminating connections, using mongo and posting to slack and webex:
```
python3 scripts/docker_honeypot.py -ports 2375 2376 2377 4243 4244 \
                   -terminate_with_error -use_mongo -mongo_host=172.17.0.2 \
                   -slack -slack_channel "#docker-alert" \
                   -slack_username="dockerhp" \
                   -slack_webhook "SLACK_WEBHOOK" \
                   -wbx -wbx_webhook "WEBEX_WEBHOOK"
```

## Testing with Commands

Run the docker honeypot with ports (2370), terminating connections, using mongo and posting to webex:
```
python3 scripts/docker_honeypot.py -ports 2370 \
                   -terminate_with_error -use_mongo -mongo_host=172.17.0.2 \                 
                   -wbx -wbx_webhook "WEBEX_HOOK"
```

Testing the banner grab with netcat connections:
```
printf "GET /v1.40/version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" | nc 127.0.0.1 2370

```

Testing the Docker honeypot server with `docker`:
```
time docker -H tcp://127.0.0.1:2370 run --rm -v /:/mnt alpine chroot /mnt /bin/sh -c "echo 'IyEvYmluL2Jhc2gKZGF0ZSArJ0ZPUk1BVCcKIAojIyMgbW0vZGQveXl5eSAjIyMKZGF0ZSArJyVtLyVkLyVZJwogCiMjIFRpbWUgaW4gMTIgaHIgZm9ybWF0ICMjIwpkYXRlICsnJXInCiAKIyMgYmFja3VwIGRpciBmb3JtYXQgIyMKYmFja3VwX2Rpcj0kKGRhdGUgKyclbS8lZC8lWScpCmVjaG8gIkJhY2t1cCBkaXIgZm9yIHRvZGF5OiAvbmFzMDQvYmFja3Vwcy8ke2JhY2t1cF9kaXJ9Igo=' | base64 -f | bash" 
```

Testing the Docker honeypot server with an HTTP Server:
```
import socket

RSP = b'HTTP/1.0 200 OK\r\n\r\n'

server = socket.socket()
server.bind(('', 2371))
server.listen(10)
try:
  while True:
    c, a = server.accept()
    data = c.recv(8192*10)
    print(data)
    c.send(RSP)
    c.close()
except KeyboardInterupt:
  pass

```

## Testing with the Collector

Collector command:
```
python3 scripts/collector.py -http_port 2371 -use_mongo -mongo_host=172.17.0.2 \                 
                   -wbx -wbx_webhook "WEBEX_HOOK"
```

Docker honeypot command:
```
python3 scripts/docker_honeypot.py -ports 2370 -terminate_with_error \
                   -http -http_url "http://127.0.0.1:2371/events"
```

## Creating Cryptographic Certificates for Infrastructure
Below are some elements of the cryptographic infrastructure needed for server and clients.  The password `CHANGEME` needs to be updated.

### Create the CA
```
# openssl genrsa -aes256 -passout pass:CHANGEME -out ca.pass.key 4096
# openssl rsa -passin pass:CHANGEME -in ca.pass.key -out ca.key
openssl req -newkey rsa:4096 -passout pass:CHANGEME -keyform PEM -keyout ca.key -x509 -days 3650 -outform PEM -out ca.cer
```

### Create the Server SSL Key
```
SERVER_ID="docker-honeypot-collector"
SERVER_SERIAL=100
openssl genrsa -out ${SERVER_ID}.key 4096
openssl req -new -key ${SERVER_ID}.key -out ${SERVER_ID}.req -sha256
openssl x509 -passin pass:CHANGEME -req -in ${SERVER_ID}.req -CA ca.cer -CAkey ca.key -set_serial ${SERVER_SERIAL} -extensions server -days 1460 -outform PEM -out ${SERVER_ID}.cer -sha256
openssl x509 -req -days 365 -in ${SERVER_ID}.req -signkey ${SERVER_ID}.key -out ${SERVER_ID}.crt
rm ${SERVER_ID}.req
```

### Create the Client
```
CLIENT_ID="docker-honeypot"
CLIENT_SERIAL=101

openssl genrsa -out ${CLIENT_ID}.key 4096
openssl req -new -key ${CLIENT_ID}.key -out ${CLIENT_ID}.req
openssl x509 -req -passin pass:CHANGEME -days 9999 -in ${CLIENT_ID}.req -CA ca.cer -CAkey ca.key -set_serial ${CLIENT_SERIAL} -out ${CLIENT_ID}.pem
openssl x509 -passin pass:CHANGEME -req -in ${CLIENT_ID}.req -CA ca.cer -CAkey ca.key -set_serial ${CLIENT_SERIAL} -extensions server -days 1460 -outform PEM -out ${CLIENT_ID}.cer -sha256
openssl x509 -req -days 365 -in ${CLIENT_ID}.req -signkey ${CLIENT_ID}.key -out ${CLIENT_ID}.crt
rm ${CLIENT_ID}.cer ${CLIENT_ID}.req
```


###
```

```
