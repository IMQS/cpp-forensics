Run test server

	env
	gcloud config set project imqs-forensics
	gcloud preview app run app.yaml

Deploy to appengine

	goapp deploy -oauth -application imqs-forensics