FROM golang:alpine as gobuild

RUN apk add --no-cache libcap-utils
WORKDIR github.com/nberlee/bonjour-reflector
COPY go.* .
RUN go mod download
COPY *.go .
RUN GOOS=linux CGO_ENABLED=0 go build -ldflags="-s -w"
RUN setcap cap_net_raw+ep bonjour-reflector
RUN chmod -w bonjour-reflector

FROM scratch
COPY --from=gobuild /go/github.com/nberlee/bonjour-reflector/bonjour-reflector /
CMD ["/bonjour-reflector"]
