FROM jfloff/alpine-python:2.7-slim

MAINTAINER Kyle Squizzato: 'kyle.squizzato@docker.com'

WORKDIR /

RUN pip install --upgrade \
    pip \
    docker \

COPY ./fixscan.py /

ENTRYPOINT ["python", "./fixscan.py"]
