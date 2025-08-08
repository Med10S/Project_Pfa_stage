# Docker Compose environments for TheHive and Cortex

>[!IMPORTANT]
> This repository contains Docker Compose files and additional resources to deploy TheHive and Cortex in both testing and production environments.


This repository offers various Docker Compose profiles to set up TheHive and Cortex for different use cases, including both testing and production environments. These profiles are designed to simplify deployment and ensure optimal performance based on your infrastructure requirements.

## Upgrade notes

> [!CAUTION]
> ElasticSearch authentication was added [by this PR](https://github.com/StrangeBeeCorp/docker/pull/14), follow these instructions to implement it in older deployments

To implement ElasticSearch authentication, we need to recreate the `.env` file and create new `index.conf`.
This is done automatically by doing the following commands:
```bash
# Pull the latest version of this codebase
git pull

# Go to the relevant profile (e.g. "testing" here)
cd ./testing

# Run the "init.sh" script
./scripts/init.sh
```

A password for ElasticSearch will be created and propagated to TheHive and Cortex.

## Available Deployment Profiles

- [Testing environment](./testing/): Deploys TheHive and Cortex on a single server for testing purposes. Requirements: 8 GB RAM, 4 vCPU.
- [Production environment #1 - TheHive](./prod1-thehive/): Single server deployment optimized for TheHive. Requirements: 16 GB RAM, 4 vCPU.
- [Production environment #1 - Cortex](./prod1-cortex): Single server deployment optimized for Cortex. Requirements: 16 GB RAM, 4 vCPU.
- [Production environment #2 - TheHive](./prod2-thehive): High-performance deployment for TheHive on a dedicated server. Requirements: 32 GB RAM, 8 vCPU.
- [Production environment #2 - Cortex](./prod2-cortex): High-performance deployment for Cortex on a dedicated server. Requirements: 32 GB RAM, 8 vCPU.


## Software requirements

These Docker Compose profiles include scripts to help you manage and optimize various resources and settings. To ensure a smooth experience with these applications, please ensure the following software is installed on the host system:

- Docker engine `v23.0.15` and later ([install instructions](https://docs.docker.com/engine/install/))
- Docker compose plugin `v2.20.2` and later ([install instructions](https://docs.docker.com/compose/install/))
- jq [https://jqlang.github.io/jq/](https://jqlang.github.io/jq/)
- Current user should have at least sudo permissions
