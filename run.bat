set GOROOT=C:\dev\tools\GoAppEngineSDK\goroot
set GOPATH=C:\dev\individual\appengine-goroot;C:\dev\tools\GoAppEngineSDK\goroot;%~dp0
rem ..\..\tools\GoAppEngineSDK\goapp.bat serve --appidentity_email_address 810484205791-3atac7rn3qko7ir82boirni393u5n6hk@developer.gserviceaccount.com --appidentity_private_key_path forensics-d63e63cc2fdb.pem .
python ..\..\tools\GoAppEngineSDK\dev_appserver.py . --appidentity_email_address 810484205791-3atac7rn3qko7ir82boirni393u5n6hk@developer.gserviceaccount.com --appidentity_private_key_path forensics-d63e63cc2fdb.pem