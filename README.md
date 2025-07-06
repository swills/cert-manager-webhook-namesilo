<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# ACME webhook for namesilo

[![Go](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/build.yml/badge.svg)](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/build.yml)
[![golangci-lint](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/golangci-lint.yml)
[![pages-build-deployment](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/pages/pages-build-deployment)
[![Release Image](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/release-docker.yml/badge.svg)](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/release-docker.yml)
[![Release Charts](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/release-charts.yml/badge.svg)](https://github.com/swills/cert-manager-webhook-namesilo/actions/workflows/release-charts.yml)

## How to use the helm chart:

Assuming you already have cert-manager deployed in the cert-manager namespace using helm:

```bash
helm repo add swills-cert-manager-webhook-namesilo https://swills.github.io/cert-manager-webhook-namesilo/
```

Create your api key secret:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: namesilo-api-key
  namespace: cert-manager
data:
  namesilo-api-key: eW91ci1hcGkta2V5
```

Create your cluster issuer:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: acme-example-com
spec:
  acme:
    email: you@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: acme-example-com-clusterissuer-private-key-secret
    solvers:
      - dns01:
          webhook:
            config:
              apiKey:
                name: namesilo-api-key
                value: namesilo-api-key
            groupName: acme.example.com
            solverName: namesilo
        selector:
          dnsZones:
            - example.com
```

Deploy the chart:
```bash
helm install --namespace cert-manager namesilo-webhook swills-cert-manager-webhook-namesilo/namesilo-webhook
```

## How to test
```bash
$ TEST_ZONE_NAME=example.com. make test
```

