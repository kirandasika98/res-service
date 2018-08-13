FROM golang:1.10 as build

RUN mkdir -p /go/src \
    && mkdir -p /go/bin \
    && mkdir -p /go/pkg

ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

WORKDIR $GOPATH/src/res-service

RUN go get -u github.com/golang/glog
RUN go get -u github.com/gorilla/mux
RUN go get -u github.com/satori/go.uuid
RUN go get -u cloud.google.com/storage
RUN go get -u github.com/mongodb/mongo-go-driver/mongo

# Move source files
COPY *.go .

# Compile the code
RUN CGO_ENABLED=0 go install -a std
RUN CGO_ENABLED=0 go build -ldflags '-d -w -s'
RUN CGO_ENABLED=0 \
    GOOS='linux' \
    go build -a \
    -ldflags '-extflags "-static"' \
    -installsuffix cgo \
    -o main .
FROM alpine
WORKDIR /app
RUN apk update \
    && apk add ca-certificates \
    && rm -rf /var/cache/apk/*

COPY auburn-hacks-gcs.json .

COPY --from=build /go/src/res-service/main .

ENTRYPOINT ./main -v=0 \
           --logtostderr=true \
           --listen_addr=:3000
