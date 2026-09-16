{{/*
Fail helm install/upgrade when the cluster is missing ADS topology.
lookup is empty during `helm template` / CI, so those runs skip the checks.

Sandbox nodes are not checked here. Whether Kata is present decides which isolation
levels exist, not whether ADS can be installed: see ads.sandboxAvailable.
*/}}
{{- define "ads.checkPrerequisites" -}}
{{- $nodes := lookup "v1" "Node" "" "" -}}
{{- if $nodes -}}
{{- $appKey := .Values.nodes.application.labelKey -}}
{{- $appVal := .Values.nodes.application.labelValue | toString -}}
{{- $appNodes := list -}}
{{- range $nodes.items -}}
{{- $labels := .metadata.labels | default dict -}}
{{- if eq (dig $appKey "" $labels | toString) $appVal -}}
{{- $appNodes = append $appNodes .metadata.name -}}
{{- end -}}
{{- end -}}
{{- if eq (len $appNodes) 0 -}}
{{- fail (printf "ADS requires at least one node labeled %s=%s (application)" $appKey $appVal) -}}
{{- end -}}
{{- $redisNs := .Values.policy.redis.namespace | default .Release.Namespace -}}
{{- $redisSvc := required "policy.redis.service is required: the policy service keeps runs in Redis" .Values.policy.redis.service -}}
{{- if not (lookup "v1" "Service" $redisNs $redisSvc) -}}
{{- fail (printf "ADS policy service requires Redis Service %s/%s for run state" $redisNs $redisSvc) -}}
{{- end -}}
{{- $mqNs := .Values.audit.rabbitmq.namespace | default .Release.Namespace -}}
{{- $mqSvc := required "audit.rabbitmq.service is required: decisions are journalled through RabbitMQ" .Values.audit.rabbitmq.service -}}
{{- if not (lookup "v1" "Service" $mqNs $mqSvc) -}}
{{- fail (printf "ADS audit requires RabbitMQ Service %s/%s to carry decisions" $mqNs $mqSvc) -}}
{{- end -}}
{{- $pgNs := .Values.audit.postgres.namespace | default .Release.Namespace -}}
{{- $pgSvc := required "audit.postgres.service is required: the journal lives in PostgreSQL" .Values.audit.postgres.service -}}
{{- if not (lookup "v1" "Service" $pgNs $pgSvc) -}}
{{- fail (printf "ADS audit requires PostgreSQL Service %s/%s for the journal" $pgNs $pgSvc) -}}
{{- end -}}
{{- end -}}
{{- end -}}
