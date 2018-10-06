package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	// listenAddr is a flag that represents which host:port that the application must use
	listenAddr *string
	// kubernetes is a flag that is used to denote if the server is running kubernetes mode
	kubernetes      *bool
	MongoCollection *string
	// GCSCredentials is a flag that is used to specify where to fetch the google cloud credentials from
	GCSCredentials *string
	// MongoConnString is a flag that is used to set which mongodb the application must connect
	MongoConnString *string
	// gcsBucket is a flag that is used to set which google cloud bucket that must used to upload resumes
	gcsBucket *string
	Hostname  string

	// MongoClient is a variable used as a global connection to the mongodb
	MongoClient *mongo.Client
	// ResumeCollection is a variable that is used as global collection manager.
	ResumeCollection *mongo.Collection
)

func init() {

	listenAddr = flag.String("listen_addr", "localhost:8001", "listening address")
	gcsBucket = flag.String("gcs_bucket", "resumes_19", "specify which gcs bucket to use")
	kubernetes = flag.Bool("kube", false, "use this flag to specify if the application running on the cluster")
	GCSCredentials = flag.String("gcs_cred", "local", "specify [cluster|local] if cluster it will look for a env variable")
	MongoConnString = flag.String("mongo_uri", "mongodb://localhost:27017", "provide the mongodb that needs to be used.")

	flag.Parse()
}
func main() {
	// this is to make sure that the logs are written to stderr
	defer glog.Flush()
	// pull the file the kube flag is set
	if *kubernetes {
		if err := pullFile(); err != nil {
			glog.Fatalf("error pulling gcs secrets file: %v", err)
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		glog.Fatalf("error while getting hostname: %v", err)
	}
	Hostname = hostname
	// application root context used where request context is not used
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// connecting to mongo server
	MongoClient, err := mongo.NewClient(*MongoConnString)
	if err != nil {
		glog.Fatalf("error: %v", err)
		os.Exit(1)
	}
	glog.Infof("connecting to %s", *MongoConnString)
	if err := MongoClient.Connect(ctx); err != nil {
		glog.Fatalf("error: %v", err)
		os.Exit(1)
	}
	ResumeCollection = MongoClient.Database("resumes").Collection("resumes_19")
	// save the gcs credentials before init
	if *GCSCredentials == "cluster" {
		if err := downloadGCSCredentials(); err != nil {
			glog.Fatalf("error: %v", err)
			os.Exit(1)
		}
	}
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
	r.HandleFunc("/resumes/update", updateResume).Methods("POST")
	r.HandleFunc("/resumes/insight/{user_id}", resumeInsight).Methods("GET")
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
	glog.V(0).Infof("handling graceful shutdown...")
	s.Shutdown(ctx)
	os.Exit(0)
}

// index is a http handler.
// Lol, it's here just for obligatory purposes. :)
func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(marshal(map[string]interface{}{"ok": true}))
}

// upload is a http handler that is triggered by the client when there is a resume for upload.
// This http handler does various check like the file extension of the uploaded file, etc. And
// determines whether it must upload the resume to gcs.
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
	// res, err := NewResume(userID, email, file, headers)
	var res *Resume
	res, err = NewResumeWithUserID(userID)
	if res != nil {
		glog.Infof("user trying to reupload a resume")
		res.file = file
	} else {
		res, err = NewResume(userID, email, file, headers)
	}
	if err := res.Upload(); err != nil {
		glog.Errorf("error: %v", err)
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

// canUpload is http handler that used as a helper. This handler is triggered by the client
// often as they want to see whether a certain user already has a resume on the database.
// Doing this only because we dont want multiple copies for the same user
func canUpload(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.URL.Query()["user_id"]
	if !ok {
		// looks like there is no user name provided
		w.WriteHeader(200)
		w.Write(marshal(map[string]interface{}{"ok": false}))
		return
	}

	res, _ := NewResumeWithUserID(userID[0])
	if res == nil {
		w.WriteHeader(200)
		w.Write(marshal(map[string]interface{}{"ok": true}))
	} else {
		w.WriteHeader(200)
		w.Write(marshal(map[string]interface{}{"ok": false}))
	}
}

// allResumes is a http handler that is triggered only by admins and used to fetch
// a json document of all resumes and their URLs
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

// updateResume is a http handler that is used side by side with the upload handler.
// This is called when the value returned from the canUpload is false.
func updateResume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	file, headers, err := r.FormFile("resume")
	if err != nil {
		glog.Errorf("error fetching form file: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false})), http.StatusBadRequest)
		return
	}
	defer file.Close()
	name := strings.Split(headers.Filename, ".")
	if name[1] != "pdf" {
		glog.Errorf("invalid file schema: %s", name[1])
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": "only pdf version is supported"})), http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		glog.Errorf("error parsing form: %v", err)
		return
	}

	userID := r.FormValue("user_id")

	resume, err := NewResumeWithUserID(userID)
	if err != nil {
		glog.Errorf("error fetching resume: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": fmt.Sprintf("error create resume: %v", err)})), http.StatusInternalServerError)
		return
	}

	resume.file = file

	if err := resume.Upload(); err != nil {
		glog.Errorf("error uploading: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": fmt.Sprintf("error create resume: %v", err)})), http.StatusInternalServerError)
		return
	}
	if err := resume.Update(r.Context()); err != nil {
		glog.Errorf("error updating: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": fmt.Sprintf("error create resume: %v", err)})), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(marshal(map[string]interface{}{"ok": true}))
}

// resumeInsight is a http handler that is triggered by the registration system
// to determine whether a user has upload their resume without having to go to the
// resumes.auburnhacks.com subdomain to verify.
func resumeInsight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	glog.Info("this endpoint is in beta will be taken down if vulnerable")
	vars := mux.Vars(r)
	userID, ok := vars["user_id"]
	if !ok {
		glog.Errorf("no id was provided, early return")
		w.Write([]byte("bye"))
		return
	}
	glog.Infof("user_id: %s", userID)
	resume, err := NewResumeWithUserID(userID)
	if err != nil {
		glog.Errorf("error while creating resume with id: %v", err)
		http.Error(w, string(marshal(map[string]interface{}{"ok": false,
			"error": fmt.Sprintf("error while creating resume with id: %v", err)})), http.StatusBadRequest)
		return
	}

	// build the resume insight from this as we are not giving out all the data
	resi := NewResumeInsightFromResume(resume)
	w.WriteHeader(http.StatusOK)
	w.Write(marshal(resi))
}

// healthz is a obligatory RPC call that is required by the kubernetes api server
func healthz(w http.ResponseWriter, r *http.Request) {
	// perform health check by connecting to mongo
	w.WriteHeader(200)
	w.Write([]byte("ok"))
}

// loggingMiddleware is a function used by the mux. It logs all the incoming HTTP requests to stderr
// for debugging purposes.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		glog.Infof("%s %s", r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

// isAuthenticated is a middleware that is used by special handler function
// if they return potentially secret information that has to regulated.
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

// enableCors is a helper function that is used to support development sanity for
// CORS headers. In production it adds a host header that can be used for debugging
func enableCors(w *http.ResponseWriter) {
	if *kubernetes == false {
		(*w).Header().Set("Access-Control-Allow-Origin", "*")
		(*w).Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, "+
				"Accept-Encoding, X-CSRF-Token, Authorization")
	}
	(*w).Header().Set("X-Served-Host", Hostname)
}

// downloadedGCSCredentials is a helper that is run to download the gcs credentials from
// env variable provisioned by kubernetes
func downloadGCSCredentials() error {
	// Looks for GCS_CREDENTIALS env variable
	if credData := os.Getenv("GCS_CREDENTIALS"); credData != "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		credPath := filepath.Join(wd, CredFileName)
		f, err := os.Create(credPath)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write([]byte(credData))
		if err != nil {
			return err
		}
	} else {
		return errors.New("env variable GCS_CREDENTIALS not set")
	}
	return nil
}

// marshal is helper function that marshals an interface and returns a byte slice.
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

// pullFile reads the env variable and writes the contents as a file in the container
func pullFile() error {
	var gcsData string
	if gcsData = os.Getenv("GCS_SECRETS"); gcsData == "" {
		return fmt.Errorf("env variable GCS_SECRET not set")
	}
	// save the file in the current wd
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	path := filepath.Join(wd, CredFileName)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(gcsData)
	if err != nil {
		return err
	}
	return nil
}
