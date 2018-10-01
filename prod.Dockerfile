FROM alpine
WORKDIR /app
RUN apk update \
    && apk add ca-certificates \
    && rm -rf /var/cache/apk/*
COPY main server
ENTRYPOINT [ "./server" ]