FROM debian:12
RUN apt-get update && apt-get install -y make gcc libssl-dev pkg-config
RUN mkdir traceroute
COPY libsupp/ /traceroute/libsupp/
COPY include/ /traceroute/include/
COPY traceroute/ /traceroute/traceroute/
COPY Makefile VERSION /traceroute/
COPY compile.sh /
RUN chmod +x ./compile.sh
RUN ./compile.sh
