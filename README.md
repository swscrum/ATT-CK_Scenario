# Attack scenario

This project is about an custom attack scenario to showcase IT security demonstrations.

Currently, it consists of an attacker client (Kali Linux), a router container that simulates the edge of the network, a victim webserver based on NGINX, and a victim Windows client. The NGINX webserver and the Windows client share an internal docker network. The Windows client also uses an egress network so it can communicate outward. The router connects the internal network to the public side and forwards only port 80 to the NGINX server.

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

Run the docker environment via

```bash
docker compose up -d
```

The Windows client keeps outbound connectivity through its egress network, while inbound access from the attacker side reaches the NGINX server only through the router's forwarded port 80.

To add more internal clients later, connect them to `internal_net` and `egress_net` as well. Do not attach Kali to those internal networks.
