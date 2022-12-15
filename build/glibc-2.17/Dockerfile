FROM centos:centos7.4.1708

LABEL version="1.0.0" \
  description="Centos Docker image for glibc 2.17 support." \
  maintainer="Cosmian <tech@cosmian.com>" \
  name="Centos glibc 2.17"

RUN yum -y groupinstall "Development Tools" && yum clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN cp ~/.cargo/bin/cargo /usr/bin/cargo
