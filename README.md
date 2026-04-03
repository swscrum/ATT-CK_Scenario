# Attack scenario

This project is about an custom attack scenario to showcase IT security demonstrations.

Currently, it consists of an attacker client (Kali Linux), a victim webserver based on NGINX, and a victim windows client. Both, the NGINX webserver and the Windows client share a internal docker network. The NGINX and the attacker Kali share a different network which simulates a public access.

## Prerequisites

1. Docker needs to be installed on the system
2. Navigate into the `Infrastructure` folder
3. Create a file named `.env` and insert the credentials of the windows client similar to the following:

```yaml
WINDOWS_USERNAME=Administrator
WINDOWS_PASSWORD=password
```

## How to run this project

### Running for the first time or on update

1. Within the `docker-compose.yml` file, TEMPORARILY add the public network to the Windows host in order to download the current Windows image from the internet like this:

```yaml
windows:
    networks:
      - public_net
      - internal_net
    [...]
```

This is a 1-time step.

2. Run the docker environment via

```bash
docker compose up -d
```

3. Revert the change within the `docker-compose.yml` file:

```yaml
windows:
    networks:
      - internal_net
    [...]
```

### Running subsequently

Run the docker environment via

```bash
docker compose up -d
```
