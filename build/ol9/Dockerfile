FROM oraclelinux:9
ARG disable_openssl
RUN dnf install -y make gcc
RUN mkdir traceroute
ADD libsupp traceroute/libsupp/
ADD include traceroute/include
ADD traceroute traceroute/traceroute/
ADD Makefile traceroute/
ADD Make.rules traceroute/
ADD Make.defines traceroute/
ADD default.rules traceroute/
ADD VERSION traceroute/
RUN mkdir /precompiled_openssl
COPY placeholder_openssl precompiled_openssl/* /precompiled_openssl
ADD compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh ${disable_openssl}
