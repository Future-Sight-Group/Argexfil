# Argexfil

## Intro

Argexfil is a tool developed by the Future Sight Group to leak the git credentails from Argocd if an attacker has the right permissions.

## Detect if user has the necessary permissions

We made a simple tool that helps identify if a user in argocd has the necessary permissions to execute this attack:

`python3 argexfil_verify.py --server SERVER --username USERNAME --password PASSWORD` 

## Tool

Argexfil is divided into four files:
- main.go: It contains the code for the malicious service
- Dockerfile: Contains the code to generate a docker image
- argocd/application.yaml: It's a kubernetes yaml to deploy the argexfil application in argocd
- manifests/argexfil.yaml: It's the kubernetes yaml that the application will deploy in the kubernetes cluster

## Useful Commands

Generate a private key: `openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048`
Generate a ceritifcate: `openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=example.com"`
Generate a image: `docker build -t futuresightgroup/argexfil:latest .` 
Push a image: `docker push futuresightgroup/argexfil:latest`