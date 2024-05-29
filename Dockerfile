FROM golang:alpine as gobuild

RUN apk add --no-cache libpcap-dev git gcc libc-dev libcap-utils upx
WORKDIR github.com/nberlee/bonjour-reflector
COPY go.* .
COPY *.go .
RUN GOOS=linux go build -ldflags="-s -w"
RUN upx bonjour-reflector
RUN setcap cap_net_raw+ep bonjour-reflector


FROM alpine as rootfs
RUN apk --no-cache add libpcap


FROM scratch as intermediate
COPY --from=rootfs /lib/*musl* /lib/
COPY --from=rootfs /usr/lib/*pcap* /usr/lib/
COPY --from=gobuild /go/github.com/nberlee/bonjour-reflector/bonjour-reflector /bonjour-reflector

FROM scratch
COPY --from=intermediate / /
CMD ["/bonjour-reflector"]
