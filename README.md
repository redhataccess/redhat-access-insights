[![Code Health](https://landscape.io/github/redhataccess/insights-client/master/landscape.svg?style=flat)](https://landscape.io/github/redhataccess/insights-client/master)

# Red Hat Access Insights Client

## Installing

On a RHEL7 box:

### Make sure the build dependencies are installed:

```bash
    ./tests/install-build-requirements
```
        
If the script fails, try to install the build requirements by hand.  If it fails because of
subscription-manager, try 'subscription-manager register --auto-attach', or just try yum without
subscription-manager.



### Next build it.

```bash
make clean install
```


### Next configure it.

1. Edit /etc/redhat-access-insights/redhat-access-insights.conf

Some things you might want to change:

1. User id, where YOUR_RHN_xxx is your RHN/Red Hat Portal username and password 

    username=YOUR_RHN_USERNAME

    password=YOUR_RHN_PASSWORD
  
1. What server to use, where DEVEL_SERVER_AND_PORT is whatever development insights server you have set up.  If left default, the client will contact Red Hat's production server

    upload_url=http://DEVEL_SERVER_AND_PORT/r/insights/uploads

    collection_rules_url=http://DEVEL_SERVER_AND_PORT/v1/static/uploader.json
 
     gpg=False

1. Random logging stuff,

    loglevel=DEBUG

    auto_config=False

    no_schedule=True


### Next run some tests:

```bash
redhat-access-insights --verbose --register

./tests/test-containers
./tests/test-containers "python ./redhat_access_insights/__init__.py"

./tests/test-new-specs
./tests/test-conditional-docker
```


