package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	MongoConnString = fmt.Sprintf(MongoConnString, *MongoUser, *MongoPassword)
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
	logrus.Infof("connecting to %s", MongoConnString)
	if err := MongoClient.Connect(ctx); err != nil {
		logrus.Errorf("error: %v", err)
		os.Exit(1)
	}
	ResumeCollection = MongoClient.Database("resumes").Collection("resumes_19")
	// init GCS
	if err := GCSInit(ctx); err != nil {
		logrus.Errorf("error: %v", err)
		os.Exit(1)
	}

	r := mux.NewRouter()
	r.Use(loggingMiddleware)

	r.HandleFunc("/", index).Methods("GET")
	r.HandleFunc("/upload", upload).Methods("POST")
	r.HandleFunc("/can_upload", canUpload).Methods("GET")

	s := http.Server{
		Handler: r,
		Addr:    *listenAddr,
	}
	logrus.Infof("server running on %s pid: %d", s.Addr, os.Getpid())
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
	w.Header().Set("Content-Type", "application/json")

	// parse and check if there is a resume
	file, headers, err := r.FormFile("resume")
	if err != nil {
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": err.Error()})), 403)
		return
	}
	defer file.Close()
	name := strings.Split(headers.Filename, ".")
	if name[1] != "pdf" {
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": fmt.Sprintf("invalid file extension: %s", name[1])})), 403)
		return
	}
	r.ParseForm()
	userID := r.FormValue("user_id")
	email := r.FormValue("email")
	if userID == "" || email == "" {
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": "user_id and email are required"})), 403)
		return
	}
	res, err := NewResume(userID, email, file, headers)
	if err != nil {
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": err.Error()})), 403)
		return
	}
	if err := res.Upload(); err != nil {
		logrus.Errorf("error: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": err.Error()})), 500)
		return
	}

	if err := res.Save(r.Context()); err != nil {
		logrus.Errorf("error: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": err.Error()})), 500)
		return
	}

	w.WriteHeader(201)
	w.Write(marshal(map[string]interface{}{"ok": true, "data": res}))
}

func canUpload(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query()["user_id"]
	res, _ := NewResumeWithUserID(userID[0])
	if res == nil {
		w.WriteHeader(200)
		w.Write(marshal(map[string]interface{}{"ok": true}))
	} else {
		w.WriteHeader(200)
		w.Write(marshal(map[string]interface{}{"ok": false}))
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		logrus.Infof("%s %s", r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
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
