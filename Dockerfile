FROM golang:1.7
MAINTAINER Alex Hornung

VOLUME /var/log/journal
VOLUME /var/lib

RUN mkdir -p /app

WORKDIR /app

ADD . /app

RUN apt-get update && apt-get install -y --no-install-recommends \
		libsystemd-dev \
	&& rm -rf /var/lib/apt/lists/*

RUN make

RUN rm -rf /usr/local/go

RUN apt-get purge -q -y gcc g++ libc6-dev make && \
	apt-get autoclean -q -y && \
	apt-get autoremove -q -y

ENTRYPOINT ["/app/dist/go-blackhole"]
