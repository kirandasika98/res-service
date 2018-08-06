package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	"github.com/mongodb/mongo-go-driver/mongo"
)

var (
	listenAddr      *string
	MongoUser       *string
	MongoPassword   *string
	MongoConnString = "mongodb://%s:%s@ds213612.mlab.com:13612/resumes"

	MongoClient      *mongo.Client
	ResumeCollection *mongo.Collection
)

func init() {
	listenAddr = flag.String("listen_addr", "localhost:8001", "listening address")
	MongoUser = flag.String("mongo_user", "svc_acc", "mongodb username")
	MongoPassword = flag.String("mongo_password", "admin123", "mongodb password")

	flag.Parse()

	MongoConnString = fmt.Sprintf(MongoConnString, MongoUser, MongoPassword)
}
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// connecting to mongo server

	s := http.Server{
		Handler: r,
		Addr:    *listenAddr,
	}
}
