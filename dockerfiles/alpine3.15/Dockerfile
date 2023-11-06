FROM alpine:3.15
ARG disable_openssl
RUN apk add gcc make bash openrc musl-dev linux-headers perl-ipc-system-simple
RUN mkdir traceroute
ADD libsupp traceroute/libsupp/
ADD include traceroute/include
ADD traceroute traceroute/traceroute/
ADD Makefile traceroute/
ADD Make.rules traceroute/
ADD Make.defines traceroute/
ADD default.rules traceroute/
ADD VERSION traceroute/
COPY placeholder_openssl openssl* /openssl
ADD compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh ${disable_openssl}
