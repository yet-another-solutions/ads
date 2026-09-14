{{/*
Expand the name of the chart.
*/}}
{{- define "ads.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ads.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ads.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ads.labels" -}}
helm.sh/chart: {{ include "ads.chart" . }}
{{ include "ads.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "ads.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ads.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ads.adsSelectorLabels" -}}
{{ include "ads.selectorLabels" . }}
app.kubernetes.io/component: ads
{{- end }}

{{- define "ads.egressSelectorLabels" -}}
{{ include "ads.selectorLabels" . }}
app.kubernetes.io/component: ads-egress-controlplane
{{- end }}

{{- define "ads.policySelectorLabels" -}}
{{ include "ads.selectorLabels" . }}
app.kubernetes.io/component: ads-policy
{{- end }}

{{- define "ads.supervisorSelectorLabels" -}}
{{ include "ads.selectorLabels" . }}
app.kubernetes.io/component: ads-supervisor
{{- end }}

{{- define "ads.auditSelectorLabels" -}}
{{ include "ads.selectorLabels" . }}
app.kubernetes.io/component: ads-audit
{{- end }}

{{/*
Whether this cluster can actually run a sandbox: a RuntimeClass plus at least one
sandbox node carrying Kata. Nobody sets this by hand — the chart looks it up and the
policy service is told the answer, because no service may ask the cluster itself.

lookup is blind during `helm template`, and there the documented topology is assumed.
*/}}
{{- define "ads.sandboxAvailable" -}}
{{- $nodes := lookup "v1" "Node" "" "" -}}
{{- if not $nodes -}}
true
{{- else -}}
{{- $sbKey := .Values.nodes.sandbox.labelKey -}}
{{- $sbVal := .Values.nodes.sandbox.labelValue | toString -}}
{{- $rcName := .Values.nodes.sandbox.runtimeClassName -}}
{{- $rc := lookup "node.k8s.io/v1" "RuntimeClass" "" $rcName -}}
{{- $handler := $rcName -}}
{{- if and $rc $rc.handler -}}
{{- $handler = $rc.handler -}}
{{- end -}}
{{- $found := false -}}
{{- if $rc -}}
{{- range $nodes.items -}}
{{- $labels := .metadata.labels | default dict -}}
{{- if eq (dig $sbKey "" $labels | toString) $sbVal -}}
{{- range (.status.runtimeHandlers | default list) -}}
{{- if or (eq .name $handler) (eq .name $rcName) -}}
{{- $found = true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $found -}}
{{- end -}}
{{- end }}

{{/*
Where a pod finds the CA it must trust to call the other services. An explicit
tls.caBundle wins; otherwise a cert-manager Certificate signed by a CA issuer already
delivers ca.crt inside the pod's own TLS secret, so no second secret is needed.
Empty means the system trust store, which will not contain a private CA.
*/}}
{{- define "ads.caBundlePath" -}}
{{- if .Values.tls.caBundle.secretName -}}
/ca/ca.crt
{{- else if .Values.tls.certManager.enabled -}}
/certs/ca.crt
{{- end -}}
{{- end }}

{{- define "ads.policyUrl" -}}
https://{{ include "ads.fullname" . }}-policy:{{ .Values.policy.service.port }}
{{- end }}

{{- define "ads.applicationNodeSelector" -}}
{{ .Values.nodes.application.labelKey }}: {{ .Values.nodes.application.labelValue | quote }}
{{- end }}

{{- define "ads.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ads.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "ads.publicBaseUrl" -}}
https://{{ .Values.ingress.hostname }}
{{- end }}

{{- define "ads.ingressSecretName" -}}
{{- if .Values.tls.certManager.enabled -}}
{{ include "ads.fullname" . }}-ingress-tls
{{- else -}}
{{ required "tls.ingressSecretName is required when tls.certManager.enabled is false" .Values.tls.ingressSecretName }}
{{- end -}}
{{- end }}

{{- define "ads.supervisorSecretName" -}}
{{- if .Values.tls.certManager.enabled -}}
{{ include "ads.fullname" . }}-supervisor-tls
{{- else -}}
{{ required "tls.supervisorSecretName is required when tls.certManager.enabled is false" .Values.tls.supervisorSecretName }}
{{- end -}}
{{- end }}

{{- define "ads.auditSecretName" -}}
{{- if .Values.tls.certManager.enabled -}}
{{ include "ads.fullname" . }}-audit-tls
{{- else -}}
{{ required "tls.auditSecretName is required when tls.certManager.enabled is false" .Values.tls.auditSecretName }}
{{- end -}}
{{- end }}

{{- define "ads.policySecretName" -}}
{{- if .Values.tls.certManager.enabled -}}
{{ include "ads.fullname" . }}-policy-tls
{{- else -}}
{{ required "tls.policySecretName is required when tls.certManager.enabled is false" .Values.tls.policySecretName }}
{{- end -}}
{{- end }}

{{- define "ads.serviceSecretName" -}}
{{- if .Values.tls.certManager.enabled -}}
{{ include "ads.fullname" . }}-service-tls
{{- else -}}
{{ required "tls.serviceSecretName is required when tls.certManager.enabled is false" .Values.tls.serviceSecretName }}
{{- end -}}
{{- end }}
