# OpenBAS Nuclei Injector

## Table of Contents

- [OpenBAS Nuclei Injector](#openbas-nuclei-injector)
  - [Prerequisites](#prerequisites)
  - [Configuration variables](#configuration-variables)
    - [OpenBAS environment variables](#openbas-environment-variables)
    - [Base injector environment variables](#base-injector-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior](#behavior)

## Prerequisites

Le connecteur Nuclei utilise RabbitMQ selon la configuration fournie par la plateforme OpenBAS.  
L’injecteur doit donc pouvoir accéder à RabbitMQ avec l’`hostname` et le `port` définis.

## Configuration variables

Les options de configuration sont définies dans `docker-compose.yml` (mode Docker) ou `config.yml` (déploiement manuel).

### OpenBAS environment variables

| Paramètre        | config.yml | Variable d'environnement Docker | Obligatoire | Description                                     |
|------------------|------------|----------------------------------|-------------|-------------------------------------------------|
| OpenBAS URL      | url        | `OPENBAS_URL`                   | Oui         | URL de la plateforme OpenBAS.                  |
| OpenBAS Token    | token      | `OPENBAS_TOKEN`                 | Oui         | Jeton d’authentification de l’admin OpenBAS.   |

### Base injector environment variables

| Paramètre        | config.yml | Variable d'environnement Docker | Défaut | Obligatoire | Description                                                                         |
|------------------|------------|----------------------------------|--------|-------------|-------------------------------------------------------------------------------------|
| Injector ID      | id         | `INJECTOR_ID`                   | /      | Oui         | Un identifiant unique (`UUIDv4`) pour cet injecteur.                               |
| Collector Name   | name       | `INJECTOR_NAME`                 |        | Oui         | Nom de l’injecteur.                                                                |
| Log Level        | log_level  | `INJECTOR_LOG_LEVEL`           | info   | Oui         | Niveau de logs (`debug`, `info`, `warn`, `error`).                                 |

## Deployment

### Docker Deployment

Construisez l’image Docker avec le `Dockerfile` fourni.

```bash
# Remplacez [IMAGE NAME] par le nom désiré
docker build . -t [IMAGE NAME]:latest
```
Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

#### Prerequisites

Nuclei must be installed and available on the system you are running.

#### Configuration

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the injector:

```shell
python3 openbas_nuclei.py
```

## Behavior

The injector enables new inject contracts, supporting the following Nuclei scan types:

### Nmap - FIN Scan

Command executed:

```shell
nmap -Pn -sF
```

### Nmap - SYN Scan

Command executed:

```shell
nmap -Pn -sS
```

### Nmap - TCP Connect Scan

Command executed:

```shell
nmap -Pn -sT
```

### Target Selection

The targets vary based on the provided options:

If type of targets is Assets:

| Targeted property | Asset property       | 
|-------------------|----------------------|
| Seen IP           | Seen IP address      |
| Local IP (first)  | IP Addresses (first) |
| Hostname          | Hostname             |

If type of targets is Manual:

- Hostnames or IP addresses are provided directly as comma-separated values.

### Resources

- Official Nmap Documentation: https://nmap.org/docs.html
- Options Explanation:
    - -Pn: Host Discovery
    - -sS: SYN Scan
    - -sT: TCP Connect Scan
    - -sF: FIN Scan
