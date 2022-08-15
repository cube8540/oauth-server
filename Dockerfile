FROM ubuntu:18.04

RUN apt-get update && apt-get install -y unzip wget vim

RUN wget https://download.java.net/java/GA/jdk16.0.1/7147401fd7354114ac51ef3e1328291f/9/GPL/openjdk-16.0.1_linux-x64_bin.tar.gz
RUN wget https://github.com/pinpoint-apm/pinpoint/releases/download/v2.4.1/pinpoint-agent-2.4.1.tar.gz
RUN wget https://services.gradle.org/distributions/gradle-7.1-bin.zip

RUN tar -xvzf openjdk-16.0.1_linux-x64_bin.tar.gz -C /lib
RUN tar -xvzf pinpoint-agent-2.4.1.tar.gz -C /lib
RUN unzip gradle-7.1-bin.zip -d /lib

ENV JAVA_HOME /lib/jdk-16.0.1
ENV GRADLE_HOME /lib/gradle-7.1

ENV PATH $JAVA_HOME/bin:$PATH
ENV PATH $GRADLE_HOME/bin:$PATH

RUN mv /lib/pinpoint-agent-2.4.1 /lib/pinpoint-agent
RUN mv /lib/pinpoint-agent/pinpoint-bootstrap-2.4.1.jar /lib/pinpoint-agent/pinpoint-bootstrap.jar

RUN mkdir /lib/oauth-server
RUN mkdir /var/log/oauth
RUN mkdir /var/log/oauth/auth
RUN mkdir /var/log/oauth/auth/root
RUN mkdir /var/log/oauth/auth/error

ARG V_VERSION
ARG V_PROFILE

ARG V_AUTH_LOG_VOLUME=/var/log/oauth/auth

ENV AUTH_VERSION=${V_VERSION}
ENV AUTH_PROFILE=${V_PROFILE}
ENV AUTH_LOG_VOLUME=${V_AUTH_LOG_VOLUME}

ADD ./build/libs/oauth-server-$AUTH_VERSION.jar /lib/oauth-server/oauth-server.jar

VOLUME ["$AUTH_LOG_VOLUME"]