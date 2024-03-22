FROM ubuntu:22.04
ARG disable_openssl
RUN apt-get update && apt-get install -y make init gcc libipc-run-perl
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
ADD compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh ${disable_openssl}
