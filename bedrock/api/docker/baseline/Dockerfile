# DOCKER-VERSION 1.2.0

FROM ubuntu:14.10
MAINTAINER John Monsod <j.monsod@samsung.com>

# make sure apt is up to date
RUN apt-get update

# install nodejs and npm
RUN apt-get install -y nodejs npm git git-core tcl8.5 wget

ADD id_rsa /tmp/
ADD setup.sh /tmp/
RUN chmod +x /tmp/setup.sh
RUN /tmp/setup.sh

