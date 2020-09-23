## About

This is a very simple server that emulates some aspects of the Docker HTTP API.  The server will respond to:
1. HTTP `GET` version
2. HTTP `GET` ping
3. HTTP `POST` create image
4. HTTP Error Code 500 in almost all other cases

The assumption is that this service is running in a cloud provider somewhere.  As of right now, the service is a simple script that runs in a shell.  When a recon event or the creation of a container is detected, the server will log the event to any of the following services:
1. Webex Teams
2. Slack
3. Mongodb
4. HTTP Collector

Furthermore, if there is a desire to pull a webpage through a honeypot.  The collector can be used to distribute the request and then retrieve the results.

## Deployment and environment

These services can be deployed several ways.  There is a `deploy.py` that will deploy all the services to Amazon AWS.  This script will create and update all the relevant _secrets_.  The services can be deployed using Python or Docker.  In these two cases, the configiration files for the honeypot and collector will need to be updated.

### Using Docker

Setup the target hosts that will be used to run each or all of the services.  Install docker on to these hosts.  

Create all the relevant SSL/TLS certificates for all the services:
```
python3 scripts/ez_certs.py -output_path ./ssl/ \
                            -common_names mongodb collector-dockerhp dockerhp \
                            -ca_name ca-collector-dockerhp
```

#### Create tokens and passwords

Create an `env` file and update the password.  This password will be used to update the `mongo_pass` in the `collector_config.json`.

The Mongo Docker relies on `env` which should be updated:
```
MONGO_INITDB_ROOT_PASSWORD=PASSWORD
MONGO_INITDB_ROOT_USERNAME=mongo_user
``` 

The configurations files also need to be updated with the relevant passwords and tokens.

##### Updating the collector configurations
Copy the ```samples/collector_config_sample.json``` to ```collector_config.json``` contains all the parameters necessary to run the collector.  This file needs to be updated with the `honeypot_tokens` and `admin_token`.  The `secret_server_key` can also be the `admin_token`.  At this time, `secret_server_token` is used as a shared key betweeen the `collector` and `dockerhp` so service to service calls can be made, like to request web pages through a particular honeypot.

If the `collector` will only be accessible in a RFC 1918 environment, update the `global_hostname` with the RFC 1918 address.  Otherwise this will be updated with the host's public IP address at when the service starts.  If Slack or WebEx Teams is being used, update the relevant _webhooks urls_.


##### Updating the dockerhp configuration
Copy the ```samples/hp_config_sample.json``` to ```hp_config.json``` contains all the parameters necessary to run the dockerhp.  This file needs to be updated with the `collector_host`, `collector_token` and `secret_server_token`.  The `secret_server_key` is used as a shared key betweeen the `collector` and `dockerhp` so service to service calls can be made, like to request web pages through a particular honeypot.

If the `dockerhp` service will only be accessible in a RFC 1918 environment, update the `global_hostname` with the RFC 1918 address.  Otherwise this will be updated with the host's public IP address at when the service starts.

#### Starting the MongoDB, Collector, and DockerHP services
To start the respective services:

1. __MongoDB:__ `docker-compose build collector_mongo && docker-compose up -d collector_mongo`
2. __Collector:__ `docker-compose build collector && docker-compose up -d collector`
3. __DockerHP:__ `docker-compose build dockerhp && docker-compose up -d dockerhp`


### Using `deploy.py`

The deployment script will read the `samples/boto_config_sample.json` and merge the command parameters used for AWS instance creation and host command execution.  Each instance node in the `boto_config_sample.json` (e.g. entries in `instance_descriptions`) contain _activities_ and each of those activities have _steps_.  The _steps_ map to _activities_ in the configuration.  These steps include commands, files to upload, etc.  These will be executed to setup the instance, configure it, and then start the Docker container.

Update the `./samples/secrets_sample.json` with all of the relevant secrets for Mongo, the collector, and the docker honeypot.  Create all the relevant SSL/TLS certificates for all the services:
```
python3 scripts/ez_certs.py -output_path ./ssl/ \
                            -common_names mongodb collector-dockerhp dockerhp \
                            -ca_name ca-collector-dockerhp
```

Create a working secrets file:
```
cp samples/secrets_sample.json prod_scecrets.json
```

Update the AWS credentials and all the relevant tokens or secrets for services.

#### Bringing up `mongodb` in AWS

Reads the configuration file, secrets, and then starts setting up the MongoDB service.  At the conclusion of the process, `prod_secrets.json` will be updated with the MongoDB Host IP address and MongoDB password, if a new one was created.

During the course of the setup and installation:
1. an AWS instance and a data volume is created, 
2. volume is mounted, 
3. SSL certificates are uploaded, 
4. `docker-compose.yaml` is uploaded, 
5. the `collector_mongodb` container is started
```
python scripts/deploy.py -config samples/boto_config_sample.json -secrets prod_secrets.json -new_secrets_file prod_secrets.json  -mongodb_up
```

#### Bringing up `collector` in AWS

Reads the configuration file, secrets, and then starts setting up the Collector service and an Alternate Collector Service (enables resilience during maintenance).  At the conclusion of the process, `prod_secrets.json` will be updated Collector and Alternate Collector Host IP address, `admin` and `honeypot` tokens, if any are created.  

1. an AWS instance and a data volume is created, 
2. SSL certificates are uploaded, 
3. `docker-compose.yaml` is uploaded, 
4. `collector_config.json` is uploaded,
5. the `collector` container is started

During the course of the setup and installation, an AWS instance is created, SSL certificates, `docker-compose.yaml`, and then the configuration file is updated and uploaded to the collector host.  The `collector` is started as a Docker container.

```
python scripts/deploy.py -config samples/boto_config_sample.json -secrets prod_secrets.json -new_secrets_file prod_secrets.json -collector_up
```

#### Bringing up `dockerhp` in AWS

Reads the configuration file, secrets, and then starts setting up the DockerHP services.  

1. an AWS instance and a data volume is created, 
2. SSL certificates are uploaded, 
3. `docker-compose.yaml` is uploaded, 
4. `hp_config.json` is uploaded,
5. the `dockerhp` container is started

During the course of the setup and installation, an AWS instance is created, SSL certificates, `docker-compose.yaml`, and then the configuration file is updated and uploaded to the collector host.  The `dockerhp` is started as a Docker container.  Three instances are started in of the specified regions.

```
python scripts/deploy.py -config samples/boto_config_sample.json \
      -secrets prod_secrets.json -new_secrets_file prod_secrets.json \
      -dockerhp_up -dockerhp_count 3 -dockerhp_regions us-east-1 us-east-2 \
```

#### Tearing everything down in AWS

Reads the configuration file, secrets, and then terminates all instances with tags corresponding with Mongodb, the collector, and the dockerhp instances in each region.

```
python scripts/deploy.py -config samples/boto_config_sample.json \
      -secrets prod_secrets.json -mongodb_down -collector_down \
      -dockerhp_down -dockerhp_regions us-east-1 us-east-2 \
```

## Requesting a Webpage

Visit ```https://COLLECTOR_HOST:5000/remote_web_request```.  Use the `admin_token` and specified the URL, any parameters/payloads, and the sensor that you wish to leverage.  When the request is executed and ready for download, notifications will be sent out to the Slack or Webex channels. 


## Testing the Docker Honeypot

With `docker` installed, execute the following host against the honeypot, replacing the `HOST` variable

```
export HOST=192.168.122.1
time docker -H tcp://${HOST}:2375 run --rm -v /:/mnt alpine chroot /mnt /bin/sh -c "echo 'IyEvYmluL2Jhc2gKZGF0ZSArJ0ZPUk1BVCcKIAojIyMgbW0vZGQveXl5eSAjIyMKZGF0ZSArJyVtLyVkLyVZJwogCiMjIFRpbWUgaW4gMTIgaHIgZm9ybWF0ICMjIwpkYXRlICsnJXInCiAKIyMgYmFja3VwIGRpciBmb3JtYXQgIyMKYmFja3VwX2Rpcj0kKGRhdGUgKyclbS8lZC8lWScpCmVjaG8gIkJhY2t1cCBkaXIgZm9yIHRvZGF5OiAvbmFzMDQvYmFja3Vwcy8ke2JhY2t1cF9kaXJ9Igo=' | base64 -f | bash"
```