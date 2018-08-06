package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/mongodb/mongo-go-driver/mongo"
	"github.com/sirupsen/logrus"
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
	MongoClient, err := mongo.NewClient(MongoConnString)
	if err != nil {
		logrus.Errorf("error: %v", err)
		os.Exit(1)
	}
	if err := MongoClient.Connect(ctx); err != nil {
		logrus.Errorf("error: %v", err)
		os.Exit(1)
	}
	ResumeCollection = MongoClient.Database("resumes").Collection("resumes_19")
	r := mux.NewRouter()
	r.Use(loggingMiddleware)

	r.HandleFunc("/", index).Methods("GET")
	r.HandleFunc("/upload", upload).Methods("POST")
	//r.HandleFunc("/resumes", allResumes).Methods("GET")

	s := http.Server{
		Handler: r,
		Addr:    *listenAddr,
	}

	go func() {
		if err := s.ListenAndServe(); err != nil {
			logrus.Errorf("error: %v", err)
			os.Exit(1)
		}
	}()
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	os.Exit(0)
}

func index(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write(marshal(map[string]interface{}{"ok": true}))
}

func upload(w http.ResponseWriter, r *http.Request) {
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: add cors stuff here
		logrus.Infof("%s %s", r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func marshal(o interface{}) []byte {
	if o == nil {
		return nil
	}
	data, err := json.Marshal(o)
	if err != nil {
		logrus.Errorf("marshal error: %v", err)
	}
	return data
}
