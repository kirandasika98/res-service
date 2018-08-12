package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/mongodb/mongo-go-driver/mongo"
)

const (
	AdminAuth = "admin:admin"
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
	// this is to make sure that the logs are written to stderr
	defer glog.Flush()
	// application root context used where request context is not used
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// connecting to mongo server
	MongoClient, err := mongo.NewClient(MongoConnString)
	if err != nil {
		glog.Fatalf("error: %v", err)
		os.Exit(1)
	}
	glog.Infof("connecting to %s", MongoConnString)
	if err := MongoClient.Connect(ctx); err != nil {
		glog.Fatalf("error: %v", err)
		os.Exit(1)
	}
	ResumeCollection = MongoClient.Database("resumes").Collection("resumes_19")
	// init GCS
	if err := GCSInit(ctx); err != nil {
		glog.Fatalf("error: %v", err)
		os.Exit(1)
	}

	r := mux.NewRouter()
	r.Use(loggingMiddleware)

	r.HandleFunc("/", index).Methods("GET")
	r.HandleFunc("/upload", upload).Methods("POST")
	r.HandleFunc("/healthz", healthz).Methods("GET")
	r.HandleFunc("/can_upload", canUpload).Methods("GET")
	r.Handle("/resumes", isAuthenticated(http.HandlerFunc(allResumes))).Methods("GET")

	s := http.Server{
		Handler: r,
		Addr:    *listenAddr,
	}
	glog.Infof("server running on %s pid: %d", s.Addr, os.Getpid())
	go func() {
		if err := s.ListenAndServe(); err != nil {
			glog.Fatalf("error: %v", err)
			os.Exit(1)
		}
	}()
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	os.Exit(0)
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
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
		glog.Fatalf("error: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": err.Error()})), 500)
		return
	}

	if err := res.Save(r.Context()); err != nil {
		glog.Fatalf("error: %v", err)
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

func allResumes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	res, err := getAllResumes(r.Context())
	if err != nil {
		glog.Fatalf("error: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": err.Error()})), 500)
		return
	}
	w.WriteHeader(200)
	w.Write(marshal(map[string]interface{}{"ok": true, "data": res}))
}

func healthz(w http.ResponseWriter, r *http.Request) {
	// perform health check by connecting to mongo
	w.WriteHeader(200)
	w.Write([]byte("ok"))
}
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		glog.Infof("%s %s", r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSlice, ok := r.Header["Authorization"]
		if !ok {
			http.Error(w, string(marshal(map[string]interface{}{"ok": false,
				"error": fmt.Sprintf("endpoint %s needs authorization", r.RequestURI)})), 401)
			return
		}
		token := strings.Split(authSlice[0], " ")
		glog.Infof("auth token: %s", token[1])
		tokenDecoded, _ := base64.StdEncoding.DecodeString(token[1])
		if string(tokenDecoded) != AdminAuth {
			http.Error(w, string(marshal(map[string]interface{}{"ok": false,
				"error": "invalid authorization"})), 401)
			return
		}
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
		glog.Fatalf("marshal error: %v", err)
	}
	return data
}
