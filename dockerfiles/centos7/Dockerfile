FROM centos:7
ARG disable_openssl
RUN yum install -y make systemd gcc perl-IPC-Cmd
RUN mkdir traceroute
ADD libsupp traceroute/libsupp/
ADD include traceroute/include
ADD traceroute traceroute/traceroute/
ADD Makefile traceroute/
ADD Make.rules traceroute/
ADD Make.defines traceroute/
ADD default.rules traceroute/
ADD VERSION traceroute/
RUN mkdir /openssl
COPY placeholder_openssl openssl* /openssl
COPY CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
ADD compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh ${disable_openssl}
