## About

This is a very simple server that emulates some aspects of the Docker HTTP API.  The server will respond to:
1. HTTP `GET` version
2. HTTP `GET` ping
3. HTTP `POST` create image
4. HTTP Error Code 500 in almost all other cases

## Environment
The assumption is that this service is running in a cloud provider somewhere.  As of right now, the service is a simple script that runs in a shell.  This can be easily converted into a docker image.  When a recon event or the creation of a container is detected, the server will log the event to any of the following services:
1. Webex Teams
2. Slack
3. Mongodb
4. HTTP Collector

**NOTE**: the HTTP collector is a work in progress and experimental.

### Setting up the EC2 Instance (assuming Ubuntu Linux 18+)
```
sudo apt update
sudo apt install docker.io tmux python3-pip
sudo systemctl status docker
sudo systemctl unmask docker
sudo systemctl status docker
sudo systemctl start docker
git clone https://github.com/ciscocsirt/dhp.git
cd dhp && sudo pip3 install .

```

## Example Command

Run the docker honeypot with ports (2375, 2376, 2377, 4243, 4244), terminating connections, using mongo and posting to slack and webex:
```
python3 scripts/docker_honeypot.py -ports 2375 2376 2377 4243 4244 \
                   -terminate_with_error -use_mongo -mongo_host=172.17.0.2 \
                   -slack -slack_channel "#docker-alert" \
                   -slack_username="dockerhp" \
                   -slack_webhook "SLACK_WEBHOOK" \
                   -wbx -wbx_webhook "WEBEX_WEBHOOK"
```
