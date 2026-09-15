{{/*
Fail helm install/upgrade when the cluster is missing ADS topology.
lookup is empty during `helm template` / CI, so those runs skip the checks.
*/}}
{{- define "ads.checkPrerequisites" -}}
{{- $nodes := lookup "v1" "Node" "" "" -}}
{{- if $nodes -}}
{{- $appKey := .Values.nodes.application.labelKey -}}
{{- $appVal := .Values.nodes.application.labelValue | toString -}}
{{- $sbKey := .Values.nodes.sandbox.labelKey -}}
{{- $sbVal := .Values.nodes.sandbox.labelValue | toString -}}
{{- $rcName := .Values.nodes.sandbox.runtimeClassName -}}
{{- $appNodes := list -}}
{{- $sbNodes := list -}}
{{- range $nodes.items -}}
{{- $labels := .metadata.labels | default dict -}}
{{- if eq (dig $appKey "" $labels | toString) $appVal -}}
{{- $appNodes = append $appNodes .metadata.name -}}
{{- end -}}
{{- if eq (dig $sbKey "" $labels | toString) $sbVal -}}
{{- $sbNodes = append $sbNodes . -}}
{{- end -}}
{{- end -}}
{{- if eq (len $appNodes) 0 -}}
{{- fail (printf "ADS requires at least one node labeled %s=%s (application)" $appKey $appVal) -}}
{{- end -}}
{{- if eq (len $sbNodes) 0 -}}
{{- fail (printf "ADS requires at least one node labeled %s=%s (sandbox)" $sbKey $sbVal) -}}
{{- end -}}
{{- $rc := lookup "node.k8s.io/v1" "RuntimeClass" "" $rcName -}}
{{- if not $rc -}}
{{- fail (printf "ADS requires RuntimeClass %s on the cluster (Kata on sandbox nodes)" $rcName) -}}
{{- end -}}
{{- $handler := $rcName -}}
{{- if $rc.handler -}}
{{- $handler = $rc.handler -}}
{{- end -}}
{{- $kataNodes := list -}}
{{- range $sbNodes -}}
{{- $labels := .metadata.labels | default dict -}}
{{- $hasKata := false -}}
{{- if eq (dig "katacontainers.io/kata-runtime" "" $labels | toString) "true" -}}
{{- $hasKata = true -}}
{{- end -}}
{{- range (.status.runtimeHandlers | default list) -}}
{{- if or (eq .name $handler) (eq .name $rcName) -}}
{{- $hasKata = true -}}
{{- end -}}
{{- end -}}
{{- if $hasKata -}}
{{- $kataNodes = append $kataNodes .metadata.name -}}
{{- end -}}
{{- end -}}
{{- if eq (len $kataNodes) 0 -}}
{{- fail (printf "ADS requires sandbox nodes (%s=%s) to have Kata (%s runtime handler or katacontainers.io/kata-runtime=true)" $sbKey $sbVal $rcName) -}}
{{- end -}}
{{- end -}}
{{- end -}}
