{{/*
Fail helm install/upgrade when the cluster is missing ADS topology
or Keycloak operator CRDs / Keycloak CR needed for realm bootstrap.
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
{{- if .Values.keycloak.bootstrap.enabled -}}
{{- if not (lookup "apiextensions.k8s.io/v1" "CustomResourceDefinition" "" "keycloaks.k8s.keycloak.org") -}}
{{- fail "ADS Keycloak realm bootstrap requires CRD keycloaks.k8s.keycloak.org (install the Keycloak operator first)" -}}
{{- end -}}
{{- if not (lookup "apiextensions.k8s.io/v1" "CustomResourceDefinition" "" "keycloakrealmimports.k8s.keycloak.org") -}}
{{- fail "ADS Keycloak realm bootstrap requires CRD keycloakrealmimports.k8s.keycloak.org (install the Keycloak operator first)" -}}
{{- end -}}
{{- $kcNs := required "keycloak.bootstrap.namespace is required when keycloak.bootstrap.enabled is true" .Values.keycloak.bootstrap.namespace -}}
{{- $kcName := required "keycloak.bootstrap.keycloakCRName is required when keycloak.bootstrap.enabled is true" .Values.keycloak.bootstrap.keycloakCRName -}}
{{- if not (lookup "k8s.keycloak.org/v2beta1" "Keycloak" $kcNs $kcName) -}}
{{- fail (printf "ADS Keycloak realm bootstrap requires Keycloak CR %s/%s" $kcNs $kcName) -}}
{{- end -}}
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
{{- if and .Values.persistence.enabled (not .Values.persistence.pv.enabled) .Values.persistence.storageClass -}}
{{- $sc := lookup "storage.k8s.io/v1" "StorageClass" "" .Values.persistence.storageClass -}}
{{- if not $sc -}}
{{- fail (printf "ADS requires StorageClass %s" .Values.persistence.storageClass) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
