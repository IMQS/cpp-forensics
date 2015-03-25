package forensics

import (
	"appengine"
	"net/http"
)

func init() {
	// Create a handler that catches a panic(Error)
	makeHandler := func(raw func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					appengine.NewContext(r).Errorf("Internal Server Error: %v", err)
					http.Error(w, err.(error).Error(), http.StatusInternalServerError)
				}
			}()
			raw(w, r)
		}
	}
	http.HandleFunc("/writedump/", makeHandler(dbWriteDump))
	http.HandleFunc("/fetch-dump-list", makeHandler(dbFetchDumpList))
	http.HandleFunc("/fetch-dump", makeHandler(dbFetchDump))
	http.HandleFunc("/write-analysis", makeHandler(dbWriteAnalysis))
	http.HandleFunc("/", makeHandler(showHome))
}
