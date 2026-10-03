# Interoperable Non-Repudiation Protocol powered by DKGs


This is the main repo of the project carried out during my research period at the University of Strathclyde under supervision of Prof. Ross Horne.

During these three weeks we worked on a novel approach to non-repudiation, which led us to consider it as a novel proposal for Non-Repudiation.

The repository is structured into four folders, one per each agent of the system, plus a lib folder containing libraries needed for the project.
For each of them, you can find the README inside the specific folder project.
### Demo App
It is a demo of an app interacting with a Solid Community Solid Server.
### Demo Issuer
It is a demo of an issuer responsible for releasing credentials to the users.
### Demo TTP
It is a demo for a Trusted Third Party, responsible for decrypting the message of the protocol
### Demo User
It is a demo for the wallet of the user, which receives credentials, create new VP and send it to the App.

## Prerequisites
You need to execute the Solid Server, and which is expected to run on the same docker network as the current project, named `solid-demo-net`. If you want to use a different url to reach the server, feel free to adapt it.

After copying the `docker-compose-template.yml` to `docker-compose.yml`, and completed with with necessary data, you can execute it with Docker 

```bash
docker network create solid-demo-net


docker compose up -d
```

## Notice
Regarding the library folder, it is important to know that the `.tgz` files you found there have been created by starting from the source code existing in the folder. 

## TODO
* Create a DIDDocument to upload in building phase, so that one can easily upload it in its POD.
