FROM golang:alpine as gobuild

RUN apk add --no-cache libpcap-dev git gcc libc-dev
WORKDIR github.com/nberlee/bonjour-reflector
COPY go.* .
COPY *.go .
RUN GOOS=linux go build -ldflags="-s -w"

FROM alpine
RUN apk --no-cache add libpcap

COPY --from=gobuild /go/github.com/nberlee/bonjour-reflector/bonjour-reflector /

CMD ["/bonjour-reflector"]
