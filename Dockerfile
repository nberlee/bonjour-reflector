FROM golang:1.22.1-alpine3.19 as gobuild

RUN apk add --no-cache libpcap-dev git gcc libc-dev libcap-utils
WORKDIR github.com/nberlee/bonjour-reflector
COPY go.* .
COPY *.go .
RUN GOOS=linux go build -ldflags="-s -w"
RUN setcap cap_net_raw+ep bonjour-reflector


FROM alpine:3.19.1 as rootfs
RUN apk --no-cache add libpcap
COPY --from=gobuild /go/github.com/nberlee/bonjour-reflector/bonjour-reflector /
RUN find /usr/bin /usr/sbin /sbin /bin  -type l -delete && busybox grep -v libpcap /etc/apk/world | busybox xargs apk del 


FROM scratch
COPY --from=rootfs / /
CMD ["/bonjour-reflector"]
