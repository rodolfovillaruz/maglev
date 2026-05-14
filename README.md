# Maglev

Maglev is a CLI tool that provisions and manages cloud-backed Kubernetes clusters on **Google Cloud Platform** and **DigitalOcean**. It reads a declarative YAML config, creates VM instances, installs Kubernetes via `kubeadm`, and deploys **Cilium** as the CNI — all over plain SSH.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Concepts](#concepts)
  - [Groups](#groups)
  - [Specs](#specs)
  - [Rules](#rules)
  - [Provisioner](#provisioner)
- [Config Reference](#config-reference)
  - [GCP](#gcp-config)
  - [DigitalOcean](#digitalocean-config)
- [Commands](#commands)
  - [apply](#apply)
  - [play](#play)
  - [reset](#reset)
  - [restart](#restart)
  - [destroy](#destroy)
  - [print](#print)
- [High Availability](#high-availability)
- [Private Nodes and Jump Hosts](#private-nodes-and-jump-hosts)
- [Control-Plane Endpoint](#control-plane-endpoint)
- [GCP Authentication](#gcp-authentication)
- [Environment Variables](#environment-variables)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Rust (edition 2024) | `cargo build --release` |
| `ssh` in `$PATH` | Used for all remote operations |
| `kubeadm` / `kubelet` / `kubectl` on each node | Installed by the startup script |
| `cilium` CLI on each control-plane node | Installed by the startup script |
| A GCP service account key **or** a DigitalOcean API token | See [Authentication](#gcp-authentication) |

---

## Installation

```bash
git clone https://github.com/your-org/maglev
cd maglev
cargo build --release
sudo install -m 755 target/release/maglev /usr/local/bin/maglev
```

---

## Concepts

### Groups

A **group** is a named collection of node names that share the same role.

```yaml
group:
  - name: primary
    type: control-plane   # "control-plane" or "worker"
    node:
      - maglev-cp-alpha
      - maglev-cp-beta
```

`type` controls how `maglev play` treats the nodes:

| Type | Behaviour |
|---|---|
| `control-plane` | First node runs `kubeadm init`; additional nodes join as control-plane members |
| `worker` | Nodes run `kubeadm join` as workers |

### Specs

A **spec** is a named template of VM configuration fields. All fields are optional so that multiple specs can be **merged**.

```yaml
specs:
  - name: cisak          # base spec — shared by every node
    config:
      - script: |
          #!/bin/bash
          ...
        ssh-public-key: ~/.ssh/id_ed25519.pub
        user: root
        machine-type: s-2vcpu-4gb
        boot-disk-image: ubuntu-24-04-x64
        control-plane-endpoint: k8s-api.example.com

  - name: primary        # role spec — adds only the disk size
    config:
      - boot-disk-size: 20

  - name: secondary
    config:
      - boot-disk-size: 50
```

#### Spec fields

| Field | Type | Description |
|---|---|---|
| `machine-type` | string | Provider-specific machine/size slug |
| `boot-disk-image` | string | OS image name or family |
| `boot-disk-size` | integer (GB) | Boot disk size |
| `ip-address` | `public` \| `private` | Whether to assign a public IP (default: `private`) |
| `ssh-public-key` | path | Path to the SSH public key (tilde expanded) |
| `user` | string | SSH login user |
| `script` | string | Cloud-init / startup script injected at boot |
| `control-plane-endpoint` | string | Stable API server address, e.g. `k8s-api.example.com:6443` |

### Rules

A **rule** binds one or more groups to an ordered list of specs. The specs are merged **left-to-right**: later entries win for any field both define.

```yaml
rules:
  - group:
      - primary
    specs:
      - cisak     # provides user, script, machine-type, image, ssh key
      - primary   # adds boot-disk-size: 20

  - group:
      - secondary
    specs:
      - cisak
      - secondary # adds boot-disk-size: 50
```

`group` accepts either a scalar or a sequence:

```yaml
# Both forms are valid:
group: worker-nodes
group:
  - worker-nodes
```

After merging, every required field (`machine-type`, `boot-disk-image`, `boot-disk-size`, `ssh-public-key`, `script`, `user`) must be present or Maglev returns an error before touching the cloud provider.

### Provisioner

The optional `provisioner` block names the node that Maglev should use as an SSH **jump host** when reaching nodes with private IPs.

```yaml
provisioner:
  type: public   # which IP type to use from the provisioner node
  node: maglev-cp-alpha
```

When absent, the first control-plane node is used as the implicit jump host.

---

## Config Reference

### GCP Config

```yaml
gcp:
  provisioner:          # optional
    type: public
    node: maglev-cp-alpha

  group:
    - name: public
      type: control-plane
      node: [maglev-cp-alpha]
    - name: private
      type: control-plane
      node: [maglev-cp-beta, maglev-cp-gamma]
    - name: worker-nodes
      type: worker
      node: [maglev-worker-alpha, maglev-worker-beta]

  specs:
    - name: cisak
      config:
        - script: |
            #!/bin/bash
            ...
          ssh-public-key: ~/.ssh/id_ed25519.pub
          user: ubuntu
          machine-type: e2-standard-2
          boot-disk-image: ubuntu-2404-lts-amd64
          control-plane-endpoint: k8s-api.example.com
    - name: control-plane-public
      config:
        - boot-disk-size: 20
          ip-address: public
    - name: control-plane-private
      config:
        - boot-disk-size: 20
    - name: worker-nodes
      config:
        - boot-disk-size: 50

  rules:
    - group: [public]
      specs: [cisak, control-plane-public]
    - group: [private]
      specs: [cisak, control-plane-private]
    - group: worker-nodes
      specs: [cisak, worker-nodes]

  credentials:
    client-email: my-sa@my-project.iam.gserviceaccount.com
    private-key: path/to/private-key.pem
    project-id: my-project
    zone: us-central1-a
```

#### GCP image names

Common families understood by Maglev's image resolver:

| Config value | Resolved path |
|---|---|
| `ubuntu-2404-lts-amd64` | `projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64` |
| `debian-12` | `projects/debian-cloud/global/images/family/debian-12` |
| Any value containing `/` | Used verbatim |

### DigitalOcean Config

```yaml
digitalocean:
  provisioner:
    type: public
    node: maglev-cp-alpha

  group:
    - name: primary
      type: control-plane
      node: [maglev-cp-alpha, maglev-cp-beta, maglev-cp-gamma]
    - name: secondary
      type: worker
      node: [maglev-worker-alpha, maglev-worker-beta]

  specs:
    - name: cisak
      config:
        - script: |
            #!/bin/bash
            ...
          ssh-public-key: ~/.ssh/id_ed25519.pub
          user: root
          machine-type: s-2vcpu-4gb
          boot-disk-image: ubuntu-24-04-x64
          control-plane-endpoint: k8s-api.example.com
    - name: primary
      config:
        - boot-disk-size: 20
    - name: secondary
      config:
        - boot-disk-size: 50

  rules:
    - group: [primary]
      specs: [cisak, primary]
    - group: [secondary]
      specs: [cisak, secondary]

  credentials:
    token: "your-digitalocean-api-token"
    region: nyc1
```

> **Note:** DigitalOcean Droplets always receive a public IP. The `ip-address: public/private` spec field controls which IP Maglev uses for SSH — it does not suppress the public IP.

#### DigitalOcean size mapping

GCP-style machine types are automatically translated:

| Config value | DO slug |
|---|---|
| `e2-standard-2` | `s-2vcpu-4gb` |
| `e2-standard-4` | `s-4vcpu-8gb` |
| `s-2vcpu-4gb` (native) | passed through unchanged |

---

## Commands

### apply

Create all VM instances described by the config.

```bash
maglev apply config/gcp.yaml
maglev apply config/digitalocean.yaml
```

Maglev resolves every rule, prints a summary of what will be created, then prompts once before making any API calls.

### play

Provision Kubernetes on an existing set of VMs.

```bash
maglev play config/gcp.yaml
maglev play config/gcp.yaml --auto-approve   # skip all interactive prompts
```

**Step 1 — Primary control-plane init**

- Checks `containerd` is running on every node.
- Verifies (and optionally fixes) `control-plane-endpoint` DNS resolution on each node.
- Writes a `kubeadm-config.yaml` with `serverTLSBootstrap: true` and runs `kubeadm init`.
- Deploys **Cilium** CNI (`cilium install` then `cilium status --wait`).

**Step 2 — Additional control-plane nodes (HA only)**

- Fetches a fresh `kubeadm join --control-plane` command from the primary node.
- Joins each additional control-plane node.

**Step 3 — Worker nodes**

- Fetches a `kubeadm join` token from the primary control-plane.
- Verifies that nodes already joined belong to *this* cluster by comparing CA fingerprints before skipping them.
- Joins any unjoined workers.

**Final — CSR approval**

Lists all `Pending` kubelet-serving CSRs (generated because `serverTLSBootstrap: true` is set) and offers a single bulk-approve prompt.

### reset

Run `kubeadm reset` on every node and remove Kubernetes state directories.

```bash
maglev reset config/gcp.yaml
```

Prompts before each node. Nodes with private IPs are reached through the jump host.

> ⚠️ **Destructive.** Any running cluster will be destroyed.

### restart

Reboot all nodes.

```bash
maglev restart config/gcp.yaml
```

### destroy

Permanently delete all VM instances listed in the config.

```bash
maglev destroy config/gcp.yaml
```

Prompts once with a clear warning before making any deletion calls.

### print

Interactive GCP credential builder.

```bash
maglev print
```

Reads credentials from `GOOGLE_APPLICATION_CREDENTIALS` or `MAGLEV_PRIVATE_KEY` / `MAGLEV_CLIENT_EMAIL`, generates a self-signed X.509 certificate from the RSA key, prints the PEM for upload to GCP IAM, and optionally saves a JSON credential file.

---

## High Availability

A cluster is considered HA when there are **three or more** control-plane nodes. Maglev will:

- Pass `--upload-certs` to `kubeadm init`.
- Include `controlPlaneEndpoint` in the kubeadm config.
- Verify the stored `controlPlaneEndpoint` in the live `kubeadm-config` ConfigMap before joining additional nodes.
- Warn when the endpoint is an even number of control-plane nodes (etcd requires an odd quorum).
- Warn when the endpoint points directly at the primary node's IP rather than a load-balancer address.

**Recommended layout:**

```
                   ┌──────────────────┐
clients ──────────▶│  Load Balancer   │  k8s-api.example.com:6443
                   └────────┬─────────┘
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
    maglev-cp-alpha   maglev-cp-beta   maglev-cp-gamma
```

Set `control-plane-endpoint: k8s-api.example.com` in the `cisak` spec and point DNS at the load-balancer.

---

## Private Nodes and Jump Hosts

When a node has `ip-address: private`, Maglev routes all SSH commands through the provisioner node using `ProxyJump`.

```
your machine
    │  ssh -i key ubuntu@<provisioner-public-ip>
    │  -o ProxyJump=ubuntu@<provisioner-public-ip>
    └──▶ provisioner (public IP)
              └──▶ target node (private IP)
```

This works transparently for every operation: `apply`, `play`, `reset`, `restart`.

---

## Control-Plane Endpoint

`control-plane-endpoint` must be resolvable on **every** node before `kubeadm` runs. Maglev checks this automatically and offers two options when the hostname is missing or incorrect:

1. **Auto-fix** — appends `<primary-cp-ip>  <hostname>` to `/etc/hosts` on the target node as a temporary placeholder.
2. **Abort** — prints the exact command to run manually on every node.

Once a real load-balancer is live, remove the `/etc/hosts` entry from every node:

```bash
sudo sed -i '/k8s-api.example.com/d' /etc/hosts
```

---

## GCP Authentication

Maglev authenticates to GCP using a **service account private key** (PKCS#8 PEM). It signs a JWT locally with `RS256`, exchanges it for a short-lived OAuth2 access token, and uses that token for all Compute Engine API calls. No `gcloud` CLI is required at runtime.

### Generating a key with `maglev print`

```bash
export MAGLEV_PRIVATE_KEY=~/.config/maglev/private-key.pem
export MAGLEV_CLIENT_EMAIL=my-sa@my-project.iam.gserviceaccount.com
maglev print
```

The command generates an RSA-2048 key if none exists, produces a self-signed X.509 certificate, and prints upload instructions for GCP IAM.

### Using an existing service account JSON

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
maglev print   # reads private_key and client_email from the JSON
```

### DigitalOcean Authentication

Set the API token directly in the config file or use an environment variable and reference it:

```yaml
credentials:
  token: "dop_v1_..."
  region: nyc1
```

---

## Environment Variables

| Variable | Used by | Description |
|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | `print` | Path to a GCP service-account JSON file |
| `MAGLEV_PRIVATE_KEY` | `print` | Path to a PEM private key (alternative to above) |
| `MAGLEV_CLIENT_EMAIL` | `print` | Service account email (used with `MAGLEV_PRIVATE_KEY`) |
| `HOME` / `USERPROFILE` | all | Used for `~` expansion in `ssh-public-key` paths |

A `.env` file in the working directory is loaded automatically via `dotenv`.
