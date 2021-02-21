FROM ubuntu:18.04

RUN apt-get -y update && \
    apt-get install -y -qq g++ openjdk-11-jdk python python3 && \
    apt-get install -y -qq build-essential

RUN mkdir -p /home/ubuntu/new_worker
COPY . /home/ubuntu/new_worker

WORKDIR /home/ubuntu/new_worker
RUN make
RUN rm *.cpp
RUN rm *.h
RUN rm Makefile Dockerfile README.md
