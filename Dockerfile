FROM ubuntu:16.04

MAINTAINER Kyle Squizzato: 'kyle.squizzato@docker.com'

WORKDIR /

RUN apt-get update -qq && apt-get install -y \
  curl \
  python2.7-minimal \
  python-pip
RUN curl -sSL https://get.docker.com/ | sh
RUN pip install --upgrade \
  pip \
  logrusformatter \
  docker

COPY ./fixscan.py /

ENTRYPOINT ["python", "./fixscan.py"]
