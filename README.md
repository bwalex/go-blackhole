# go-blackhole

[![Build Status](https://api.travis-ci.org/bwalex/go-blackhole.svg?branch=master)](https://travis-ci.org/bwalex/go-blackhole)

go-blackhole watches the systemd journal for failed SSH login/authentication attempts and automatically blacklists these IPs for a fixed duration by adding a blackhole route.

## Get it

Release binaries for linux amd64 platforms are built by default and can be downloaded from the [Releases page](https://github.com/bwalex/go-blackhole/releases).

A Docker image is also available: [bwalex/go-blackhole](https://hub.docker.com/r/bwalex/go-blackhole/). Check out [example/k8s-blackhole.yaml](example/k8s-blackhole.yaml) for a usage example as a Kubernetes DaemonSet.

For other platforms or to build from source, clone the repository and just run `make`.

## Usage

    Usage of dist/go-blackhole:
      -blacklist-duration duration
        	blacklist duration (default 30m0s)
      -db string
        	database file location (default "/var/lib/blackhole.db")
      -ipv4-prefix int
        	IPv4 prefix length to blacklist (default 32)
      -ipv6-prefix int
        	IPv6 prefix length to blacklist (default 64)
      -journal-path string
        	systemd journal path (default "/var/log/journal")
