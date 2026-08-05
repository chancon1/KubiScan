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

REPORT_MODE="${KUBISCAN_REPORT_MODE:-events}"
rm -f /tmp/report.json /tmp/kubiscan.log

if [ "$REPORT_MODE" = "events" ]; then
  if ! python3 /opt/kubiscan/KubiScan.py \
    -q \
    -co /tmp/kubeconfig \
    -ctx in-cluster \
    --risk-events \
    -j /tmp/report.json >/tmp/kubiscan.log 2>&1; then
    cat /tmp/kubiscan.log >&2
    exit 1
  fi
elif [ "$REPORT_MODE" = "roles" ]; then
  if ! python3 /opt/kubiscan/KubiScan.py \
    -q \
    -co /tmp/kubeconfig \
    -ctx in-cluster \
    -rar \
    -r \
    -j /tmp/report.json >/tmp/kubiscan.log 2>&1; then
    cat /tmp/kubiscan.log >&2
    exit 1
  fi
else
  echo "KUBISCAN_REPORT_MODE must be 'events' or 'roles', got: $REPORT_MODE" >&2
  exit 2
fi

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
