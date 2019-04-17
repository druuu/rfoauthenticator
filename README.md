# rfoauthenticator
customize oauthenticator to use sso_user in auth0 as username for jupyterhub

# packaging
```sh
rm sdist/*
python setup.py sdist
twine upload sdist/*
```
