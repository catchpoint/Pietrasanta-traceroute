FROM oraclelinux:9
RUN dnf install -y make gcc openssl-devel
RUN mkdir traceroute
COPY libsupp/ /traceroute/libsupp/
COPY include/ /traceroute/include/
COPY traceroute/ /traceroute/traceroute/
COPY Makefile VERSION /traceroute/
COPY compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh
