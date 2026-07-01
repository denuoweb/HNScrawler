# Cloud Audit

Corrected local `gcloud` context:

- account: `hns-browser-submit-testers@hns-browser.iam.gserviceaccount.com`
- project: `denuowebsite`
- configured compute zone: unset
- configured compute region: unset

The local project was initially set to `crowdpmplatform`; it was corrected with:

```bash
gcloud config set project denuowebsite
```

Read-only Compute Engine inventory against `denuowebsite` is currently blocked for the active service account:

```text
The resource 'projects/denuowebsite' was not found
Project 'denuowebsite' not found or permission denied
```

Project discovery is also blocked because Cloud Resource Manager is not usable from this account/context.

No GCP APIs were enabled and no cloud resources were created. Before provisioning the ephemeral indexer VM, confirm the active account has access to the `denuowebsite` project and set the zone/VM variables explicitly:

```bash
export GCP_PROJECT="denuowebsite"
export GCP_ZONE="us-west1-b"
export INDEXER_VM="hns-topology-indexer"
export INDEXER_DISK="hns-topology-indexer-disk"
```

Then run:

```bash
scripts/gcloud-create-indexer.sh
```

The script creates or starts the compute VM and keeps the indexer disk persistent with `auto-delete=no`.
