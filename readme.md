Download dependencies

	Download and install `Google App Engine SDK for Go` into C:\Google\Cloud-SDK

	set GOPATH=<this directory>
	go get code.google.com/p/go-uuid/uuid

Run test server

	Get the authentication key from passpack "imqs-forensics service key" and save it as forensics-d63e63cc2fdb.pem

	run.bat

Deploy to appengine

	To avoid interruption in services, first deploy the app to a new version say version 3

	deploy.bat 3

	then transfer all traffic to this new version in Google App Engine console. Switch off the old version once you have checked everything is working as expected.