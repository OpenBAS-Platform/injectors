# OpenBAS Nuclei Injector

## Table of Contents

- [OpenBAS Nuclei Injector](#openbas-nuclei-injector)
  - [Prerequisites](#prerequisites)
  - [Configuration Variables](#configuration-variables)
    - [OpenBAS Environment Variables](#openbas-environment-variables)
    - [Base Injector Environment Variables](#base-injector-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior](#behavior)

## Prerequisites

This injector connects to RabbitMQ based on the configuration provided by the OpenBAS platform.  
Make sure the injector can reach RabbitMQ on the specified hostname and port.

## Configuration Variables

Configuration is done via `docker-compose.yml` (for Docker) or `config.yml` (for manual deployment).

### OpenBAS Environment Variables

| Parameter       | config.yml | Docker Environment Variable | Required | Description                                      |
|-----------------|------------|-----------------------------|----------|--------------------------------------------------|
| OpenBAS URL     | url        | `OPENBAS_URL`               | Yes      | The base URL of the OpenBAS platform.           |
| OpenBAS Token   | token      | `OPENBAS_TOKEN`             | Yes      | The default admin token from the OpenBAS UI.    |

### Base Injector Environment Variables

| Parameter       | config.yml | Docker Environment Variable | Default | Required | Description                                                                           |
|-----------------|------------|-----------------------------|---------|----------|---------------------------------------------------------------------------------------|
| Injector ID     | id         | `INJECTOR_ID`               | /       | Yes      | A unique `UUIDv4` identifier for this injector instance.                             |
| Injector Name   | name       | `INJECTOR_NAME`             |         | Yes      | The name of the injector.                                                            |
| Log Level       | log_level  | `INJECTOR_LOG_LEVEL`        | info    | Yes      | Logging verbosity: `debug`, `info`, `warn`, or `error`.                              |

## Deployment

### Docker Deployment

Build the Docker image using the provided `Dockerfile`:

```bash
docker build . -t [IMAGE_NAME]:latest
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
