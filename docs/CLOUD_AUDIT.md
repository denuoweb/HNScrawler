# Cloud Audit

Corrected local `gcloud` context:

- account: `jaron.rosenau@gmail.com`
- project: `denuo-web-site`
- configured compute zone: unset
- configured compute region: unset

The local project was initially set to `crowdpmplatform`, then briefly to the display/name shorthand `denuowebsite`. The actual GCP project ID is `denuo-web-site`; it was corrected with:

```bash
gcloud config set account jaron.rosenau@gmail.com
gcloud config set project denuo-web-site
```

Read-only Compute Engine inventory now succeeds:

```text
NAME         ZONE        STATUS   MACHINE_TYPE  DISK_SIZE_GB  NETWORK_IP  NAT_IP
denuoweb-vm  us-west1-b  RUNNING  e2-micro      ['30']        10.138.0.2  35.212.156.128
```

Disk inventory:

```text
NAME         ZONE        SIZE_GB  TYPE         USERS            STATUS
denuoweb-vm  us-west1-b  30       pd-standard  ['denuoweb-vm']  READY
```

Read-only SSH check:

```text
/dev/sda1  30G  19G  9.7G  66% /
/var/www/denuoweb/index.html
```

No GCP APIs were enabled and no cloud resources were created. Before provisioning the ephemeral indexer VM, set the zone/VM variables explicitly:

```bash
export GCP_PROJECT="denuo-web-site"
export GCP_ZONE="us-west1-b"
export INDEXER_VM="hns-topology-indexer"
export INDEXER_DISK="hns-topology-indexer-disk"
```

Then run:

```bash
scripts/gcloud-create-indexer.sh
```

The script creates or starts the compute VM and keeps the indexer disk persistent with `auto-delete=no`.
