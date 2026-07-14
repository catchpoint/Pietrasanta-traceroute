FROM oraclelinux:9
RUN dnf install -y make gcc openssl-devel
RUN mkdir traceroute
ADD libsupp traceroute/libsupp/
ADD include traceroute/include
ADD traceroute traceroute/traceroute/
ADD Makefile traceroute/
ADD VERSION traceroute/
ADD compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh
