{{/*
Offline helm template/lint cannot look up cluster resources. A real install,
upgrade, or server-side dry run must see kube-system (lookup errors fail Helm).
Do not gate security checks on the existing topology Node list.
*/}}
{{- define "ads.checkSandboxAdmission" -}}
{{- $applicationNamespace := required "namespace is required" .Values.namespace -}}
{{- $namespace := required "sandbox.namespace is required" .Values.sandbox.namespace -}}
{{- if or (eq $namespace .Release.Namespace) (eq $applicationNamespace .Release.Namespace) -}}
{{- fail "store the Helm release in a separate existing namespace (use --namespace default), not a chart-managed workload namespace" -}}
{{- end -}}
{{- if eq $namespace $applicationNamespace -}}
{{- fail "namespace and sandbox.namespace must be distinct" -}}
{{- end -}}
{{- $admission := .Values.sandbox.admission -}}
{{- $kyvernoNamespace := required "sandbox.admission.kyvernoNamespace is required" $admission.kyvernoNamespace -}}
{{- range (list $namespace $applicationNamespace) -}}
{{- if or (eq . $kyvernoNamespace) (has . (list "default" "kube-system" "kube-public" "kube-node-lease")) -}}
{{- fail "namespace and sandbox.namespace must be dedicated ADS workload namespaces" -}}
{{- end -}}
{{- end -}}
{{- if lookup "v1" "Namespace" "" "kube-system" -}}
{{- if not (lookup "v1" "Namespace" "" .Release.Namespace) -}}
{{- fail "the Helm release namespace must already exist (use --namespace default)" -}}
{{- end -}}
{{- $crd := lookup "apiextensions.k8s.io/v1" "CustomResourceDefinition" "" "clusterpolicies.kyverno.io" -}}
{{- if not $crd -}}
{{- fail "ADS requires Kyverno to be installed first: missing clusterpolicies.kyverno.io CRD" -}}
{{- end -}}
{{- $established := false -}}
{{- range (dig "status" "conditions" (list) $crd) -}}
{{- if and (eq .type "Established") (eq .status "True") -}}
{{- $established = true -}}
{{- end -}}
{{- end -}}
{{- if not $established -}}
{{- fail "ADS requires an established Kyverno ClusterPolicy CRD" -}}
{{- end -}}
{{- $deployment := lookup "apps/v1" "Deployment" $kyvernoNamespace $admission.deploymentName -}}
{{- if not $deployment -}}
{{- fail (printf "ADS requires Kyverno admission Deployment %s/%s" $kyvernoNamespace $admission.deploymentName) -}}
{{- end -}}
{{- if lt (int (dig "status" "availableReplicas" 0 $deployment)) 1 -}}
{{- fail "ADS requires an available Kyverno admission controller" -}}
{{- end -}}
{{- $sa := lookup "v1" "ServiceAccount" $kyvernoNamespace $admission.serviceAccountName -}}
{{- if not $sa -}}
{{- fail "ADS requires the configured Kyverno admission ServiceAccount" -}}
{{- end -}}
{{- end -}}
{{- end -}}
