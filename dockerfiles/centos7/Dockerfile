ARG openssl3_folder
FROM centos:7
RUN yum install -y make systemd gcc
RUN mkdir traceroute
ADD libsupp traceroute/libsupp/
ADD include traceroute/include
ADD traceroute traceroute/traceroute/
ADD Makefile traceroute/
ADD Make.rules traceroute/
ADD Make.defines traceroute/
ADD default.rules traceroute/
ADD VERSION traceroute/
ADD openssl3_folder traceroute/

CMD ["/sbin/init"]
