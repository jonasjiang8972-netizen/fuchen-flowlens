# 拂尘 FlowLens · Flink image with connector jars baked in
# Jars placed in deploy/flink/lib/ (Kafka + JDBC + ClickHouse driver) are copied
# onto the Flink classpath. See submit.sh for the download commands.
FROM flink:1.18-scala_2.12-java11

# Build context is deploy/flink. Missing jars fail the job submission later,
# not this build.
COPY lib/ /opt/flink/lib/
COPY api_events_pipeline.sql /opt/flink/sql/api_events_pipeline.sql
