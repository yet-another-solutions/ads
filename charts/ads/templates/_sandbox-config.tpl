{{- define "ads.sandboxName" -}}
{{- printf "%s-sandbox-%s" (include "ads.fullname" .root) .component -}}
{{- end -}}

{{- define "ads.sandboxImage" -}}
{{- printf "%s:%s" .image.repository (default .root.Chart.AppVersion .image.tag) -}}
{{- end -}}

{{- define "ads.sandboxSecret" -}}
{{- default (include "ads.sandboxName" .) .settings.existingSecret -}}
{{- end -}}

{{- define "ads.sandboxTLS" -}}
{{- if .root.Values.tls.certManager.enabled -}}
{{- printf "%s-tls" (include "ads.sandboxName" .) -}}
{{- else -}}
{{- required (printf "sandbox.%s.tlsSecretName is required for BYO TLS" .component) .settings.tlsSecretName -}}
{{- end -}}
{{- end -}}

{{/* Same integer quantity grammar as manager/golden; check before multiplication. */}}
{{- define "ads.storageBytes" -}}
{{- $q := toString . -}}
{{- if not (regexMatch "^[0-9]+(Ki|Mi|Gi|Ti|Pi|k|M|G|T|P)?$" $q) -}}
{{- fail "storage sizes must be positive integer Kubernetes quantities" -}}
{{- end -}}
{{- $digits := regexFind "^[0-9]+" $q -}}
{{- $suffix := trimPrefix $digits $q -}}
{{- $factors := dict "" 1 "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 "Pi" 1125899906842624 "k" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 "P" 1000000000000000 -}}
{{- $factor := int64 (index $factors $suffix) -}}
{{- $n := int64 $digits -}}
{{- if or (gt (len $digits) 19) (le $n 0) (gt $n (div (int64 "9223372036854775807") $factor)) -}}
{{- fail "storage sizes must fit positive signed 64-bit bytes" -}}
{{- end -}}
{{- mul $n $factor -}}
{{- end -}}

{{- define "ads.checkSandboxValues" -}}
{{- $sb := .Values.sandbox -}}
{{- $version := printf "v%s" .Chart.AppVersion -}}
{{- if or (not (regexMatch "^v[0-9]+\\.[0-9]+\\.[0-9]+(-[a-z0-9]+([.-][a-z0-9]+)*)?$" $version)) (gt (len (printf "ads-sandbox-golden-%s" $version)) 63) -}}
{{- fail "Chart.appVersion must be a DNS-safe ADS release version" -}}
{{- end -}}
{{- if hasKey $sb "sessionSize" -}}
{{- fail "sandbox.sessionSize is not configurable: session size is baked into the release" -}}
{{- end -}}
{{- $release := .Files.Get "files/sandbox-release.yaml" | fromYaml -}}
{{- $size := include "ads.storageBytes" $release.sessionSize | int64 -}}
{{- $slack := include "ads.storageBytes" $sb.golden.slack | int64 -}}
{{- if lt $slack 2147483648 -}}
{{- fail "sandbox.golden.slack must be at least 2Gi" -}}
{{- end -}}
{{- if gt $size (sub (int64 "9223372036854775807") $slack) -}}
{{- fail "session size plus golden slack exceeds signed 64-bit bytes" -}}
{{- end -}}
{{- $_ := include "ads.storageBytes" $sb.ipc.size -}}
{{- if or (not $sb.ipc.storageClass) (eq $sb.ipc.storageClass "sandbox-block") -}}
{{- fail "sandbox.ipc.storageClass must be an existing application Filesystem class, not sandbox-block" -}}
{{- end -}}
{{- if ne .Values.nodes.sandbox.runtimeClassName "kata-qemu" -}}
{{- fail "sandbox v1 requires RuntimeClass kata-qemu" -}}
{{- end -}}
{{- if or (le (float64 .Values.engine.mcpTimeoutSeconds) 0.0) (not (regexMatch "^[0-9]+(\\.[0-9]+)?$" (toString .Values.engine.mcpTimeoutSeconds))) -}}
{{- fail "engine.mcpTimeoutSeconds must be positive" -}}
{{- end -}}
{{- if or (lt (int64 .Values.engine.maxToolCalls) 1) (not (regexMatch "^[0-9]+$" (toString .Values.engine.maxToolCalls))) -}}
{{- fail "engine.maxToolCalls must be a positive integer" -}}
{{- end -}}
{{- range $component, $settings := dict "manager" $sb.manager "mcp" $sb.mcp "ipc" $sb.ipc -}}
{{- range $key, $value := $settings -}}
{{- if or (hasSuffix "Seconds" $key) (hasSuffix "Bytes" $key) (has $key (list "replicaCount" "port" "topicReplicationFactor" "lifecycleBatch")) -}}
{{- if not (regexMatch "^[0-9]+(\\.[0-9]+)?$" (toString $value)) -}}
{{- fail (printf "sandbox.%s.%s must be a positive number" $component $key) -}}
{{- end -}}
{{- if le (float64 $value) 0.0 -}}
{{- fail (printf "sandbox.%s.%s must be positive" $component $key) -}}
{{- end -}}
{{- if and (or (not (hasSuffix "Seconds" $key)) (eq $key "bakeSeconds")) (not (regexMatch "^[0-9]+$" (toString $value))) -}}
{{- fail (printf "sandbox.%s.%s must be an integer" $component $key) -}}
{{- end -}}
{{- if and (eq $key "port") (gt (int $value) 65535) -}}
{{- fail (printf "sandbox.%s.port must be at most 65535" $component) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if le (float64 $sb.manager.pingTimeoutSeconds) (float64 $sb.manager.pingIntervalSeconds) -}}
{{- fail "sandbox.manager.pingTimeoutSeconds must exceed pingIntervalSeconds" -}}
{{- end -}}
{{- if le (float64 $sb.manager.recoverySeconds) (float64 $sb.manager.cleanupSeconds) -}}
{{- fail "sandbox.manager.recoverySeconds must exceed cleanupSeconds" -}}
{{- end -}}
{{- if not (has $sb.manager.kafka.securityProtocol (list "PLAINTEXT" "SSL" "SASL_PLAINTEXT" "SASL_SSL")) -}}
{{- fail "unsupported sandbox.manager.kafka.securityProtocol" -}}
{{- end -}}
{{- if and (hasPrefix "SASL" $sb.manager.kafka.securityProtocol) (not $sb.manager.existingSecret) -}}
{{- $_ := required "manager Kafka SASL username is required" $sb.manager.kafka.saslUsername -}}
{{- $_ := required "manager Kafka SASL password is required" $sb.manager.kafka.saslPassword -}}
{{- end -}}
{{- end -}}

{{- define "ads.sandboxSessionObjects" -}}
{{- $sb := .Values.sandbox -}}
{{- $ipc := dict "root" . "component" "ipc" "settings" $sb.ipc -}}
{{- $selector := mergeOverwrite (dict) .Values.nodeSelector (dict .Values.nodes.application.labelKey (toString .Values.nodes.application.labelValue)) -}}
{{- $objects := dict
  "guest_image" (include "ads.sandboxImage" (dict "root" . "image" $sb.guest.image))
  "ipc_image" (include "ads.sandboxImage" (dict "root" . "image" $sb.ipc.image))
  "ipc_storage_class" $sb.ipc.storageClass
  "ipc_service_account" "ads-sandbox-ipc"
  "ipc_config_map" (include "ads.sandboxName" $ipc)
  "ipc_secret" (include "ads.sandboxSecret" $ipc)
  "ipc_tls_secret" (include "ads.sandboxTLS" $ipc)
  "ipc_node_selector" $selector
  "ipc_size" $sb.ipc.size
  "guest_resources" $sb.guest.resources
  "ipc_resources" $sb.ipc.resources
  "ipc_tolerations" .Values.tolerations
  "create_seconds" $sb.manager.createSeconds -}}
{{- if $sb.ipc.caSecretName -}}
{{- $_ := set $objects "ipc_ca_secret" $sb.ipc.caSecretName -}}
{{- end -}}
{{- $objects | toJson -}}
{{- end -}}
