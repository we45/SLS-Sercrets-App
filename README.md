# SLS-Sercrets-App

* Install the necessary SLS Plugins

```bash
sls plugin install -n serverless-python-requirements && sls plugin install -n serverless-wsgi
```

* Deploy the Lambda Function

```bash
sls deploy
```

* Signup for an account

```bash
http POST <sls-endpoint>/signup email=test@test.com password=hello
```

* Login to get the JWT token

```bash
http POST <sls-endpoint>/login email=test@test.com password=hello
```

* Create a new Credit Card Entry

```bash
http POST <sls-endpoint>/create-card ccn=4111111111111111 Authorization:<JWT_TOKEN>
```

* Fetch the Credit Card Number

```bash
http GET <sls-endpoint>/get-card Authorization:<JWT_TOKEN>
```