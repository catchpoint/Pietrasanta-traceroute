FROM oraclelinux:8.10
RUN dnf install -y epel-release
RUN dnf config-manager --enable ol8_developer_EPEL && dnf install -y make gcc openssl3-devel
RUN mkdir traceroute
COPY libsupp/ /traceroute/libsupp/
COPY include/ /traceroute/include/
COPY traceroute/ /traceroute/traceroute/
COPY Makefile VERSION /traceroute/
COPY compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh
