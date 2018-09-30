package main

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"github.com/golang/glog"
	"github.com/mongodb/mongo-go-driver/bson"
	uuid "github.com/satori/go.uuid"
)

const (
	ResumeBucket = "resumes_19"
	GCSPubURL    = "https://storage.googleapis.com/%s/%s"
	CredFileName = "auburn-hacks-gcs.json"
)

var GCSClient *storage.Client

func GCSInit(ctx context.Context) error {
	// cred file is always saved in the current dir as the binary
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	credFile := filepath.Join(wd, CredFileName)
	if err = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credFile); err != nil {
		return err
	}

	// creating a GCS client
	GCSClient, err = storage.NewClient(ctx)
	if err != nil {
		return err
	}
	return nil
}

type Resume struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	URL    string `json:"url"`
	file   multipart.File
}

func NewResume(userID string, email string, file multipart.File,
	header *multipart.FileHeader) (*Resume, error) {
	uuid, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	filename := uuid.String() + path.Ext(header.Filename)
	r := Resume{
		UserID: userID,
		Name:   filename,
		Email:  email,
		file:   file,
	}
	return &r, nil
}

func NewResumeWithUserID(userID string) (*Resume, error) {
	var r Resume
	idFilter := bson.NewDocument(bson.EC.String("userid", userID))
	err := ResumeCollection.FindOne(context.Background(), idFilter).Decode(&r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func NewResumeWithEmail(email string) (*Resume, error) {
	var r Resume
	idFilter := bson.NewDocument(bson.EC.String("email", email))
	err := ResumeCollection.FindOne(context.Background(), idFilter).Decode(&r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Upload uploads a resume to google cloud and returns the public URL and an error if any
func (r *Resume) Upload() error {
	// set up connection with gcs and start upload the resume
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wc := GCSClient.Bucket(ResumeBucket).Object(r.Name).NewWriter(ctx)

	// TODO: change the ACL rules to be anything other than public, look at signedURL's
	wc.ACL = []storage.ACLRule{{Entity: storage.AllUsers, Role: storage.RoleReader}}
	if _, err := io.Copy(wc, r.file); err != nil {
		glog.Fatalf("Error: %s", err.Error())
		return err
	}
	if err := wc.Close(); err != nil {
		glog.Fatalf("Error: %s", err.Error())
		return err
	}
	r.URL = fmt.Sprintf(GCSPubURL, string(ResumeBucket), string(r.Name))
	return nil
}

func (r *Resume) Save(ctx context.Context) error {
	doc, err := bson.Marshal(r)
	if err != nil {
		return err
	}
	_, err = ResumeCollection.InsertOne(ctx, doc)
	if err != nil {
		return err
	}
	return nil
}

func getAllResumes(ctx context.Context) ([]Resume, error) {
	cur, err := ResumeCollection.Find(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	resumes := []Resume{}
	var r Resume
	for cur.Next(ctx) {
		br, err := cur.DecodeBytes()
		if err != nil {
			return nil, err
		}
		if err := bson.Unmarshal(br, &r); err != nil {
			return nil, err
		}
		resumes = append(resumes, r)
	}
	return resumes, nil
}
