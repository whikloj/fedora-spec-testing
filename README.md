USE
===

To use the repository, you'll need Fedora, Python3 and pip. Virtualenv is reccommeded, but not required.

Use pip to install requests and pytest, as in the requirements.txt file: `pip install -r ./requirements.txt`

The script expects Fedora's rest endpoint to be available at `http://127.0.0.1:8080/rest`

If you have the Fedora source code, you can use the following commands:

    mvn clean install -pl fcrepo-webapp -Pone-click
    java -jar fcrepo-webapp/target/fcrepo-webapp-5.0.0-SNAPSHOT-jetty-console.jar --headless

Then, from this directory, run `./api-spec.py`

### Configuration

The `api-spec.py` script accepts 3 arguments

```
--baseurl=
```

To define the root of your repository

```
--username=
--password=
```

To define a username/password for authentication
