from setuptools import setup

setup(
    name="rfoauthenticator",
    version="3.7",
    description="oauthenticator custom auth0 authentication",
    author="refactored",
    author_email="info@refactored.ai",
    install_requires=["oauthenticator", "requests"],
    packages=["rfoauthenticator"],
    zip_safe=False,
)
