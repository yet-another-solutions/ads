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

{{- define "ads.serviceSecretName" -}}
{{- if .Values.tls.certManager.enabled -}}
{{ include "ads.fullname" . }}-service-tls
{{- else -}}
{{ required "tls.serviceSecretName is required when tls.certManager.enabled is false" .Values.tls.serviceSecretName }}
{{- end -}}
{{- end }}
