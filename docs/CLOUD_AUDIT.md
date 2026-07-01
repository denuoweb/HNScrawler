# Cloud Audit

Current local `gcloud` context at repository bootstrap time:

- account: `hns-browser-submit-testers@hns-browser.iam.gserviceaccount.com`
- project: `crowdpmplatform`
- configured compute zone: unset
- configured compute region: unset

Read-only Compute Engine inventory failed because `compute.googleapis.com` is disabled for `crowdpmplatform`.

No GCP APIs were enabled and no cloud resources were created from this project context. Before provisioning the ephemeral indexer VM, set the intended project, zone, and VM variables explicitly:

```bash
export GCP_PROJECT="actual-denuo-project"
export GCP_ZONE="us-west1-b"
export INDEXER_VM="hns-topology-indexer"
export INDEXER_DISK="hns-topology-indexer-disk"
```

Then run:

```bash
scripts/gcloud-create-indexer.sh
```

The script creates or starts the compute VM and keeps the indexer disk persistent with `auto-delete=no`.

