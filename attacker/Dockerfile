FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y hydra openssh-client && \
    rm -rf /var/lib/apt/lists/*

CMD [ "bash" ]