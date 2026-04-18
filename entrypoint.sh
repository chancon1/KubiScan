#!/bin/sh
set -e

TOKEN="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

cat > /tmp/kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- name: in-cluster
  cluster:
    server: https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}
    certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
users:
- name: kubiscan-sa
  user:
    token: ${TOKEN}
contexts:
- name: in-cluster
  context:
    cluster: in-cluster
    user: kubiscan-sa
current-context: in-cluster
EOF

export KUBECONFIG=/tmp/kubeconfig

python3 /opt/kubiscan/KubiScan.py \
  -co /tmp/kubeconfig \
  -ctx in-cluster \
  -rar \
  -r \
  -j /tmp/report.json 2>&1 | tail -1

python3 - <<'PYEOF'
import json, datetime
with open('/tmp/report.json') as f:
    data = json.load(f)
ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
for section in data:
    for key, items in section.items():
        for item in items:
            event = {
                'scan_timestamp': ts,
                'scan_tool': 'kubiscan',
                'section': key,
            }
            event.update(item)
            print(json.dumps(event))
PYEOF
