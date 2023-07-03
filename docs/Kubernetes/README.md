# Kubernetes deployment

## Prepare network
All vlans that need to be reflected should be tagged to the kubernetes node(s) interface. If you only want to to run the reflector exclusively on one node, you can use the `nodeName` in the deployment yaml.

## Create configmap
The configmap is created by kustomize. Please make sure to change the `config.toml` to your needs. See the [config.md](../config.md) for detailed explaination.

## Cilium
If you are running Cilium as your CNI, you need to add the following to your cilium configmap:
```yaml
    vlan-bpf-bypass: "0"
```
This will prevent cilium from dropping tagged packets.


## Deploy
The manifests in manifests/ will create a namespace, deployment and configmap. The deployment will run on the host network, so it can access the vlans. The configmap is mounted as a volume in the container.

```bash
kubectl apply -k manifests/
```