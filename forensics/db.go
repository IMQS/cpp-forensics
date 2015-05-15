package forensics

import (
	"appengine"
	"appengine/blobstore"
	"appengine/datastore"
	"code.google.com/p/go-uuid/uuid"
	"encoding/ascii85"
	"fmt"
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

const singleAttachmentKey = 1

type guidString string

type Event struct {
	AppName      string
	Host         string
	Date         time.Time
	DumpAnalysis string `datastore:",noindex"`
}

type Attachment struct {
	Blob       appengine.BlobKey `datastore:",noindex"`
	IsAnalyzed bool
}

func dbWriteDump(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	id := guidString(r.URL.Query().Get("id"))
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

	var blobKey appengine.BlobKey
	if r.ContentLength != 0 {
		blobWriter, err := blobstore.Create(c, "application/octet-stream")
		if err != nil {
			panic(err)
		}
		if _, err = io.Copy(blobWriter, r.Body); err != nil {
			panic(err)
		}
		r.Body.Close()
		if err = blobWriter.Close(); err != nil {
			panic(err)
		}
		blobKey, err = blobWriter.Key()
		if err != nil {
			panic(err)
		}

		attachment := &Attachment{
			Blob:       blobKey,
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

func dbFetchDumpList(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	q := datastore.NewQuery(minidumpKind).Filter("IsAnalyzed =", false).Limit(10).KeysOnly()
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

func dbFetchDump(w http.ResponseWriter, r *http.Request) {
	id := guidString(r.URL.Query().Get("id"))
	c := appengine.NewContext(r)
	attach := fetchAttachment(c, minidumpKind, id)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"minidump-%v.mdmp\"", id))
	blobstore.Send(w, attach.Blob)
}

func dbWriteAnalysis(w http.ResponseWriter, r *http.Request) {
	id := guidString(r.URL.Query().Get("id"))
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

func eventKey(c appengine.Context, id guidString) *datastore.Key {
	return datastore.NewKey(c, eventKind, encodeGuidString(id), 0, nil)
}

func attachmentKey(c appengine.Context, kind string, id guidString) *datastore.Key {
	return datastore.NewKey(c, kind, "", singleAttachmentKey, eventKey(c, id))
}

func fetchAttachment(c appengine.Context, kind string, id guidString) *Attachment {
	attach := &Attachment{}
	if err := datastore.Get(c, attachmentKey(c, kind, id), attach); err != nil {
		panic(err)
	}
	return attach
}

func fetchEvent(c appengine.Context, id guidString) *Event {
	event := &Event{}
	if err := datastore.Get(c, eventKey(c, id), event); err != nil {
		panic(err)
	}
	return event
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
	return guidString(g.String())
}
