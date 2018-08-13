FROM alpine
WORKDIR /app
COPY ./main .
COPY ./auburn-hacks-gcs.json .
ENV PROD 1
EXPOSE 80 
ENTRYPOINT ["./main", "--listen_addr=:80"]

