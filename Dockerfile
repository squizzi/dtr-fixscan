FROM docker:18-dind

MAINTAINER Kyle Squizzato: 'kyle.squizzato@docker.com'

WORKDIR /

RUN apk add --no-cache \
    curl \
    python
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python get-pip.py
RUN pip install --upgrade \
    logrusformatter \
    docker

COPY ./fixscan.py /

ENTRYPOINT ["python", "./fixscan.py"]
