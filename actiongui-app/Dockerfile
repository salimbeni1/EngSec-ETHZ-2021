# Set maven as base image
# Helpful for Apple M1 chips
#FROM --platform=linux/arm64 maven:3.5-jdk-8
FROM maven:3.5-jdk-8

# Copy maven settings, containing repository configurations

RUN mkdir -p /root/.m2 \
    && mkdir /root/.m2/repository

COPY settings.xml /root/.m2


#Install mySQL to connect to DB container
RUN apt-get update && apt-get -y install mysql-server
 


CMD [ "tail", "-F", "run"] 