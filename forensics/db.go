package forensics

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/ascii85"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/cloud"
	"google.golang.org/cloud/storage"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const eventKind = "Event"
const minidumpKind = "MiniDump"
const alblogKind = "AlbLog"
const albvidKind = "AlbVid"

const gcsBucket = "imqs-forensics-blobs"

const singleAttachmentKey = 1

type guidString string

type Event struct {
	AppName      string
	Host         string
	Date         time.Time
	DumpAnalysis string `datastore:",noindex"`
}

type Attachment struct {
	IsAnalyzed bool
}

func newCloudContext(appengineContext context.Context) context.Context {
	hc := &http.Client{
		Transport: &oauth2.Transport{
			Source: google.AppEngineTokenSource(appengineContext, storage.ScopeFullControl),
			Base:   &urlfetch.Transport{Context: appengineContext},
		},
	}
	return cloud.NewContext(appengine.AppID(appengineContext), hc)
}

func dbWriteDump(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	id := makeGuidString(r.URL.Query().Get("id"))
	host := r.URL.Query().Get("host")
	if id == "" {
		panic(fmt.Errorf("No 'id' specified"))
	}
	if host == "" {
		panic(fmt.Errorf("No 'host' specified"))
	}

	// Path looks like /writedump/minidump, or /writedump/alblog, etc
	paths := strings.Split(r.URL.Path, "/")
	blobtype := ""
	if len(paths) >= 3 {
		// We assume that in this code path, ContentLength != 0
		blobtype = paths[2]
	}

	event := &Event{}
	eventkey := eventKey(c, id)
	err := datastore.Get(c, eventkey, event)
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			// Create new entry
			event.Date = time.Now()
			event.Host = host
			event.AppName = r.URL.Query().Get("appname")
			_, err = datastore.Put(c, eventkey, event)
		}
		if err != nil {
			panic(err)
		}
	}

	if r.ContentLength != 0 {
		ctx := newCloudContext(c)
		fileWriter := storage.NewWriter(ctx, gcsBucket, gcsFilename(blobtype, id))
		fileWriter.ContentType = "application/octet-stream"
		written, err := io.Copy(fileWriter, r.Body)
		if err != nil {
			panic(err)
		}
		err = fileWriter.Close()
		r.Body.Close()
		log.Debugf(c, "Wrote %v bytes to %v/%v (%v)", written, gcsBucket, gcsFilename(blobtype, id), err)

		// Write 'Attachment' record, which is a child of the event record
		attachment := &Attachment{
			IsAnalyzed: false,
		}
		blobKind := blobTypeToKind(blobtype)
		attachmentKey := datastore.NewKey(c, blobKind, "", singleAttachmentKey, eventkey)
		_, err = datastore.Put(c, attachmentKey, attachment)
		if err != nil {
			panic(err)
		}
	}

	http.Error(w, "", http.StatusOK)
}

func dbDelete(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	host := r.URL.Query().Get("Host")
	if host == "" {
		http.Error(w, "No host specified", http.StatusBadRequest)
		return
	}

	q := datastore.NewQuery(eventKind).Filter("Host=", host).Limit(500).KeysOnly()
	keys, err := q.GetAll(c, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = datastore.DeleteMulti(c, keys); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Error(w, fmt.Sprintf("Deleted %v elements", len(keys)), http.StatusOK)
}

func dbFetchDumpList(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	q := datastore.NewQuery(minidumpKind).Filter("IsAnalyzed=", false).Limit(10).KeysOnly()
	keys, err := q.GetAll(c, nil)
	if err != nil {
		panic(err)
	}

	ids := ""
	for _, key := range keys {
		guid := decodeGuidString(key.Parent().StringID())
		ids += string(guid) + ","
	}
	if len(ids) != 0 {
		ids = ids[:len(ids)-1]
	}
	w.Write([]byte(ids))
}

// We could probably do this better by making the dumps public and just linking directly to them,
// but this works alright.
func dbFetchDump(w http.ResponseWriter, r *http.Request) {
	id := makeGuidString(r.URL.Query().Get("id"))
	c := appengine.NewContext(r)

	ctx := newCloudContext(c)
	fileReader, err := storage.NewReader(ctx, gcsBucket, gcsFilename(kindToBlobType(minidumpKind), id))
	if err != nil {
		log.Errorf(c, "Unable to read minidump %v/%v: %v", gcsBucket, gcsFilename(kindToBlobType(minidumpKind), id), err)
		panic(err)
	}
	defer fileReader.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"minidump-%v.mdmp\"", id))
	w.WriteHeader(http.StatusOK)
	io.Copy(w, fileReader)
}

func dbWriteAnalysis(w http.ResponseWriter, r *http.Request) {
	id := makeGuidString(r.URL.Query().Get("id"))
	c := appengine.NewContext(r)
	attach := fetchAttachment(c, minidumpKind, id)
	attach.IsAnalyzed = true
	if _, err := datastore.Put(c, attachmentKey(c, minidumpKind, id), attach); err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		panic(err)
	}

	event := fetchEvent(c, id)
	event.DumpAnalysis = string(body)
	if _, err := datastore.Put(c, eventKey(c, id), event); err != nil {
		panic(err)
	}

	http.Error(w, "", http.StatusOK)
}

func eventKey(c context.Context, id guidString) *datastore.Key {
	return datastore.NewKey(c, eventKind, encodeGuidString(id), 0, nil)
}

func attachmentKey(c context.Context, kind string, id guidString) *datastore.Key {
	return datastore.NewKey(c, kind, "", singleAttachmentKey, eventKey(c, id))
}

func fetchAttachment(c context.Context, kind string, id guidString) *Attachment {
	attach := &Attachment{}
	if err := datastore.Get(c, attachmentKey(c, kind, id), attach); err != nil {
		panic(err)
	}
	return attach
}

func gcsFilename(blobType string, id guidString) string {
	return blobType + "/dump-" + string(id) + ".mdmp"
}

func fetchEvent(c context.Context, id guidString) *Event {
	event := &Event{}
	if err := datastore.Get(c, eventKey(c, id), event); err != nil {
		panic(err)
	}
	return event
}

func kindToBlobType(kind string) string {
	switch kind {
	case minidumpKind:
		return "minidump"
	case albvidKind:
		return "albvid"
	case alblogKind:
		return "alblog"
	}
	return "unknown"
}

func blobTypeToKind(blobType string) string {
	switch blobType {
	case "minidump":
		return minidumpKind
	case "albvid":
		return albvidKind
	case "alblog":
		return alblogKind
	}
	return "unknown"
}

func makeGuidString(guid string) guidString {
	return guidString(strings.ToLower(guid))
}

func encodeGuidString(guid guidString) string {
	u := uuid.Parse(string(guid))
	encoded := [20]byte{}
	ascii85.Encode(encoded[:], u)
	return string(encoded[:])
}

func decodeGuidString(ascii85_guid string) guidString {
	decoded := [16]byte{}
	ascii85.Decode(decoded[:], []byte(ascii85_guid), true)
	g := uuid.UUID(decoded[:])
	return makeGuidString(g.String())
}
