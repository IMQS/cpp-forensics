package forensics

import (
	"appengine"
	"appengine/datastore"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

type dumpAnalysis struct {
	Exception   string
	Instruction string
	StackTrace  []string
	CrashLine   string
}

func showHome(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			http.Error(w, r.(error).Error(), http.StatusInternalServerError)
		}
	}()
	c := appengine.NewContext(r)
	q := datastore.NewQuery(eventKind).Order("-Date").Limit(60)
	var events []Event
	if _, err := q.GetAll(c, &events); err != nil {
		panic(err)
	}

	head := `<!DOCTYPE html>
	<html>
	<script src='/www/jzed.js'></script>
	<style>` + htmlStyles + `
	</style>
	<script>
	` + htmlJS + `
	</script>
	<body>
	`

	mid := ""
	for i, ev := range events {
		mid += fmt.Sprintf("<div id='trace-line-%v' class='line'>", i)
		mid += "<div class='date'>" + html.EscapeString(ev.Date.Format(time.RFC822Z)) + "</div>"
		mid += "<div class='appname'>" + html.EscapeString(ev.AppName) + "</div>"
		mid += "<div class='host'>" + html.EscapeString(ev.Host) + "</div>"
		if ev.DumpAnalysis == "" {
			mid += "<div class='trace-heading'>No stack trace yet</div>"
		} else {
			analysis := &dumpAnalysis{}
			json.Unmarshal([]byte(ev.DumpAnalysis), &analysis)
			mid += "<div class='trace-heading'>" + analysisSummaryHTML(analysis) + "</div>"
			mid += fmt.Sprintf("<div id='trace-detail-%v' class='trace-detail trace-detail-hidden'>", i) + analysisDetailHTML(analysis) + "</div>"
		}
		mid += "</div>\n"
	}

	tail := `</body>
	</html>`

	w.Write([]byte(head))
	w.Write([]byte(mid))
	w.Write([]byte(tail))
}

func analysisSummaryHTML(a *dumpAnalysis) string {
	crash := html.EscapeString(a.CrashLine)
	exception := html.EscapeString(a.Exception)
	return "<span class='crashline'>" + crash + "</span> <span class='exception'>" + exception + "</span>"
}

func analysisDetailHTML(a *dumpAnalysis) string {
	trace := "<pre>" + html.EscapeString(strings.Join(a.StackTrace, "\n")) + "</pre>"
	trace += "<pre>" + html.EscapeString(a.Instruction) + "</pre>"
	return trace
}

const htmlJS = `

function findLineNum(ev) {
	var target = ev.target;
	while (target.id == "" && $parent(target)) {
		target = $parent(target);
	}
	// extract X from 'trace-detail-X'
	return target.id.match(/\w+-\w+-(\d+)/)[1];
}

function openCrash(ev) {
	var idDetail = "trace-detail-" + findLineNum(ev);
	$toggle($id(idDetail), "trace-detail-hidden");
}

$boot(function onboot() {
	$on($name("body")[0], "click", openCrash);
});
`

const htmlStyles = `
	.line {
		display: block;
		margin: 2px 2px 2px 2px;
		cursor: pointer;
	}
	.date {
		display: inline-block;
		width: 11em;
	}
	.appname {
		display: inline-block;
		width: 8em;
	}
	.host {
		display: inline-block;
		width: 10em;
	}
	.trace-heading {
		display: inline-block;
		width: 80em;
		margin-bottom: 8px;
	}
	.crashline {
		padding: 2px 4px;
		border-radius: 2px;
		border: solid 1px #77a;
		background: #eef;
	}
	.exception {
		padding: 2px 4px;
		border-radius: 2px;
		border: solid 1px #a77;
		background: #fee;
	}
	.trace-detail {
		position: relative;
	}
	.trace-detail-hidden {
		display: none;
	}
`
