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
Below are the parameters you'll need to set for OpenBAS:
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

## Manual Deployment

### Prerequisites

You must have [Nuclei](https://nuclei.projectdiscovery.io/) installed and available in your system's `PATH`.

### Configuration

1. Copy the sample config file:

```bash
cp config.yml.sample config.yml
```

#### Prerequisites

You must have Nuclei installed and available in your system's PATH.

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

The Nuclei injector supports contract-based scans by dynamically constructing and executing Nuclei commands based on provided tags or templates.

## Supported Contracts

The following scan types are supported via `-tags`:

- Cloud
- Misconfiguration
- Exposure
- Panel
- XSS
- WordPress
- HTTP

The CVE scan uses the `-tags cve` argument and enforces JSON output.

The Template scan accepts a manual template via `-t <template>` or `template_path`.

## Target Selection

Targets are selected based on the `target_selector` field.

### If target type is **Assets**:

| Selected Property | Uses Asset Field         |
|-------------------|-------------------------|
| Seen IP           | endpoint_seen_ip         |
| Local IP          | First IP from endpoint_ips |
| Hostname          | endpoint_hostname       |

### If target type is **Manual**:

Direct comma-separated values of IPs or hostnames are used.

## Example Execution

A sample command executed by this injector might look like:

```bash
nuclei -u 192.168.1.10 -tags xss
```
Or with a specific template:
```bash
nuclei -u 10.0.0.5 -t cves/2021/CVE-2021-1234.yaml -j
```
## Output Parsing
- The injector captures and parses the JSON output of Nuclei, and returns:

- Confirmed findings (if any) with severity and CVE IDs

- Other lines as unstructured output


## Target Selection

The targets vary based on the provided input type:

### If target type is **Assets**:

| Targeted Property   | Source Property        |
|---------------------|------------------------|
| Seen IP             | Seen IP address        |
| Local IP (first)    | IP Addresses (first)   |
| Hostname            | Hostname               |

### If target type is **Manual**:

- Hostnames or IP addresses are provided directly as comma-separated values.

## Results

Scan results are categorized into:

- **CVEs** (based on template classifications)
- **Other vulnerabilities** (general issues found)

If no vulnerabilities are detected, the injector will clearly indicate this with a **"Nothing Found"** message.

## Resources

- Official Nuclei Documentation: [https://nuclei.projectdiscovery.io](https://nuclei.projectdiscovery.io)
- Template directory: [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
