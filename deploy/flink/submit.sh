#!/usr/bin/env bash
# 拂尘 FlowLens · submit the Flink streaming job (v0.7.0)
#
# Usage:
#   deploy/flink/submit.sh
#
# Assumes the stack was started with deploy/poc/docker-compose.stream.yaml
# (docs/DATA_PIPELINE.md) and the required connector jars have been placed in
# deploy/flink/lib before the flink image was built (see below).
set -euo pipefail

JOBMANAGER="${JOBMANAGER:-flowlens-flink-jobmanager-1}"
SQL_FILE="/opt/flink/sql/api_events_pipeline.sql"

# Connector jars that must exist in deploy/flink/lib/ (mounted to /opt/flink/lib).
# Download once, e.g.:
#   FLINK_VER=1.18.1
#   curl -L -o deploy/flink/lib/flink-sql-connector-kafka-3.1.0-1.18.jar \
#     https://repo.maven.apache.org/maven2/org/apache/flink/flink-sql-connector-kafka/3.1.0-1.18/flink-sql-connector-kafka-3.1.0-1.18.jar
#   curl -L -o deploy/flink/lib/flink-connector-jdbc-3.1.2-1.18.jar \
#     https://repo.maven.apache.org/maven2/org/apache/flink/flink-connector-jdbc/3.1.2-1.18/flink-connector-jdbc-3.1.2-1.18.jar
#   curl -L -o deploy/flink/lib/clickhouse-jdbc-0.6.0-all.jar \
#     https://repo.maven.apache.org/maven2/com/clickhouse/clickhouse-jdbc/0.6.0/clickhouse-jdbc-0.6.0-all.jar

# The SQL carries a placeholder so no password is committed. Take it from the
# environment or from deploy/poc/.env.
if [ -z "${CLICKHOUSE_PASSWORD:-}" ] && [ -f "$(dirname "$0")/../poc/.env" ]; then
  CLICKHOUSE_PASSWORD="$(grep -E '^CLICKHOUSE_PASSWORD=' "$(dirname "$0")/../poc/.env" | cut -d= -f2-)"
fi
: "${CLICKHOUSE_PASSWORD:?set CLICKHOUSE_PASSWORD (or put it in deploy/poc/.env)}"
export CLICKHOUSE_PASSWORD

echo "Submitting FlowLens Flink job via ${JOBMANAGER} ..."
# Letters and digits only: awk gsub treats & and \ in the replacement specially.
docker exec "${JOBMANAGER}" cat "${SQL_FILE}" \
  | awk '{ gsub(/__CLICKHOUSE_PASSWORD__/, ENVIRON["CLICKHOUSE_PASSWORD"]); print }' \
  | docker exec -i "${JOBMANAGER}" bash -c 'cat > /tmp/job.sql && $FLINK_HOME/bin/sql-client.sh -f /tmp/job.sql; rm -f /tmp/job.sql'
echo "Submitted. Track it in the Flink dashboard (port 8081 inside the compose network)."
