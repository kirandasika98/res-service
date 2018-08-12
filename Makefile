build:
	go build -v
run:
	./res-service -logtostderr=true \
		-v=0 \
		--listen_addr=:8000
clean:
	rm res-service
