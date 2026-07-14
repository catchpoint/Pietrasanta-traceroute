FROM debian:12
RUN apt-get update && apt-get install -y make gcc libssl-dev pkg-config
RUN mkdir traceroute
ADD libsupp traceroute/libsupp/
ADD include traceroute/include
ADD traceroute traceroute/traceroute/
ADD Makefile traceroute/
ADD VERSION traceroute/
ADD compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh
