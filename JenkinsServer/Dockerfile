FROM jenkins/jenkins:2.414.3-jdk17

USER root
RUN curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh && rm get-docker.sh
RUN apt-get update && apt-get install -y --no-install-recommends\
    wget \
    tree \
    jq \
    && rm -rf /var/lib/apt/list/* \
    && curl -kL https://bootstrap.pypa.io/get-pip.py | python \
    && pip install sbomdiff=0.53

ARG syft_version=1.0.1
ARG grype_version=0.74.7

RUN mkdir /tmp/syfttmp && \
    mkdir /tmp/grypetmp && \
    wget -P /tmp/syfttmp/  https://github.com/anchore/syft/releases/download/v${syft_version}/syft_${syft_version}_linux_amd64.tar.gz && \
    wget -P /tmp/grypetmp/  https://github.com/anchore/grype/releases/download/v${grype_version}/grype_${grype_version}_linux_amd64.tar.gz && \
    tar xvf /tmp/syfttmp/syft_${syft_version}_linux_amd64.tar.gz -C /tmp/syfttmp && \
    tar xvf /tmp/grypetmp/grype_${grype_version}_linux_amd64.tar.gz -C /tmp/grypetmp && \
    mv /tmp/syfttmp/syft /usr/local/bin/ && \
    mv /tmp/grypetmp/grype /usr/local/bin/

USER jenkins

