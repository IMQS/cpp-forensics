set GOPATH=C:\Google\Cloud-SDK\google-cloud-sdk\platform\google_appengine\gopath;%~dp0
rem goapp serve --appidentity_email_address 810484205791-3atac7rn3qko7ir82boirni393u5n6hk@developer.gserviceaccount.com --appidentity_private_key_path forensics-d63e63cc2fdb.pem .
dev_appserver.py . --appidentity_email_address 810484205791-3atac7rn3qko7ir82boirni393u5n6hk@developer.gserviceaccount.com --appidentity_private_key_path forensics-d63e63cc2fdb.pem
