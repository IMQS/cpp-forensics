Download dependencies

	Download and install `Google App Engine SDK for Go` into C:\dev\tools\GoAppEngineSDK

	set GOPATH=<this directory>
	go get code.google.com/p/go-uuid/uuid

Run test server

	Get the authentication key from passpack "imqs-forensics service key" and save it as forensics-d63e63cc2fdb.pem

	run.bat

Deploy to appengine

	deploy.bat