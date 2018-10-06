// resume.go implements all the function that are used by the http handlers in main.go.
// This could probably be split into a separate package, but oh well!
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
	// GCSPubURL is a constant that represents the structure of a download link
	// for a object on google cloud
	GCSPubURL = "https://storage.googleapis.com/%s/%s"
	// CredFileName is a constant that is used as the credentials filename
	// used to connect to google cloud storage
	CredFileName = "auburn-hacks-gcs.json"
)

// GCSClient is a variable that holds the active connection
// to google cloud storage
var GCSClient *storage.Client

// GCSInit is a function that is run at the beginning of the program
// to estabilish a connection to google cloud storage
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

// Resume is a struct that contains all the data for a resume
type Resume struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	URL    string `json:"url"`
	file   multipart.File
}

// NewResume is a function that creates a new resume from the
// userID, email, file and headers
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

// NewResumeWithUserID is a function that returns an instance of
// a resume from the database based on the userID provided
func NewResumeWithUserID(userID string) (*Resume, error) {
	var r Resume
	idFilter := bson.NewDocument(bson.EC.String("userid", userID))
	err := ResumeCollection.FindOne(context.Background(), idFilter).Decode(&r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// NewResumeWithEmail is a function that returns an instance
// of a resume from the database based on the email provided
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
	wc := GCSClient.Bucket(*gcsBucket).Object(r.Name).NewWriter(ctx)

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
	r.URL = fmt.Sprintf(GCSPubURL, string(*gcsBucket), string(r.Name))
	return nil
}

// Save is a function that saves an instance of a resume to
// mongodb and returns an error if any
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

// Update is a function that updates an instance of a resume and
// saves it in the database for persistance
func (r *Resume) Update(ctx context.Context) error {
	filter := bson.NewDocument(
		bson.EC.String("userid", r.UserID),
	)
	updateDoc := bson.NewDocument(
		bson.EC.SubDocumentFromElements("$set",
			bson.EC.String("url", r.URL),
		),
		bson.EC.SubDocumentFromElements(
			"$currentDate", bson.EC.Boolean("lastModified", true),
		),
	)
	_, err := ResumeCollection.UpdateOne(ctx, filter, updateDoc)
	if err != nil {
		return err
	}

	return nil
}

// getAllResumes is a function that get all the resumes and
// returns an array. This function must only be called by admins
// and will only be used to show the sponsors all the remsumes they need to see
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

// ResumeInsight is a struc that is used as an auxilary datastructure to resume when an external service
// queries the resume server. It only contains minimal data that can be useful to the client.
type ResumeInsight struct {
	UserID string `json:"user_id,omitempty"`
	Name   string `json:"name,omitempty"`
	URL    string `json:"url,omitempty"`
}

// NewResumeInsightFromResume is a function that returns a ResumeInsight from a Resume.
// This function is usually used at the end of a http handler to return only minimal
// data to the client.
func NewResumeInsightFromResume(r *Resume) *ResumeInsight {
	ri := new(ResumeInsight)
	ri.Name = r.Name
	ri.URL = r.URL
	ri.UserID = r.UserID
	return ri
}
