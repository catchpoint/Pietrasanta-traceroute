FROM oraclelinux:8.10
RUN dnf install -y epel-release
RUN dnf config-manager --enable ol8_developer_EPEL && dnf install -y make gcc openssl3-devel
RUN mkdir traceroute
ADD libsupp traceroute/libsupp/
ADD include traceroute/include
ADD traceroute traceroute/traceroute/
ADD Makefile traceroute/
ADD VERSION traceroute/
ADD compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh
