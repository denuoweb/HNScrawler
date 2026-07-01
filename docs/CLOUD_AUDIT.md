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
NAME         STATUS   MACHINE_TYPE  DEVICE_NAME
denuoweb-vm  RUNNING  e2-micro      ['denuoweb-vm', 'hns-topology-data']
```

Disk inventory:

```text
NAME               SIZE_GB  TYPE         USERS            STATUS
hns-topology-data  200      pd-standard  ['denuoweb-vm']  READY
```

Read-only SSH check:

```text
/dev/sda1  30G   19G  9.7G  66% /
/dev/sdb   196G  32K  196G   1% /mnt/hns-topology
/var/www/denuoweb/hns-topology -> /mnt/hns-topology/site
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

## Latest Preflight

`scripts/gcloud-production-preflight.sh` passed on 2026-07-01 with:

```text
production website VM:
NAME         STATUS   MACHINE_TYPE  DEVICE_NAME
denuoweb-vm  RUNNING  e2-micro      ['denuoweb-vm', 'hns-topology-data']

production artifact disk:
NAME               SIZE_GB  TYPE         USERS            STATUS
hns-topology-data  200      pd-standard  ['denuoweb-vm']  READY

production mount/path:
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        30G   19G  9.7G  66% /
/dev/sdb        196G   32K  196G   1% /mnt/hns-topology
/var/www/denuoweb/hns-topology -> /mnt/hns-topology/site

indexer VM:
NAME                  STATUS      MACHINE_TYPE   DEVICE_NAME
hns-topology-indexer  TERMINATED  e2-standard-2  ['persistent-disk-0', 'hns-topology-indexer-disk']

indexer disk:
NAME                       SIZE_GB  TYPE         USERS                     STATUS
hns-topology-indexer-disk  200      pd-balanced  ['hns-topology-indexer']  READY
```

Current production resources:

- `denuoweb-vm`
- `denuoweb-vm` boot disk
- `hns-topology-data` production artifact disk
- `hns-topology-indexer` terminated indexer VM
- `hns-topology-indexer-disk` persistent indexer data disk
