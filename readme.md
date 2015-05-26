Download dependencies

	set GOPATH=<this directory>\..\appengine-goroot  (it doesn't matter what directory you use here, so long as it's outside of the project root)
	go get google.golang.org/cloud
	go get google.golang.org/cloud/storage
	go get google.golang.org/appengine/urlfetch

	set GOPATH=<this directory>
	go get code.google.com/p/go-uuid/uuid

Run test server

	Get the authentication key from passpack "imqs-forensics service key" and save it as forensics-d63e63cc2fdb.pem

	env
	gcloud config set project imqs-forensics
	gcloud preview app run app.yaml --appidentity-email-address 810484205791-3atac7rn3qko7ir82boirni393u5n6hk@developer.gserviceaccount.com --appidentity-private-key-path forensics-d63e63cc2fdb.pem

Deploy to appengine

	set PATH=%PATH%;c:\python27_x64
	goapp deploy -application imqs-forensics