# DOCKER-VERSION 1.2.0

FROM jmsamsung/bedrock:0.1
MAINTAINER John Monsod <j.monsod@samsung.com>

# make sure apt is up to date
#RUN apt-get update

# script that checks out latest source and starts node
ADD startnode.sh /tmp/
RUN chmod +x /tmp/startnode.sh

# starts redis and node server
ADD startup.sh /tmp/
RUN chmod +x /tmp/startup.sh
ENTRYPOINT /tmp/startup.sh

