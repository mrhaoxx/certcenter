{{- define "certcenter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "certcenter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "certcenter.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "certcenter.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "certcenter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certcenter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "certcenter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "certcenter.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "certcenter.configSecretName" -}}
{{- default (include "certcenter.fullname" .) .Values.existingSecret -}}
{{- end -}}

{{- define "certcenter.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* The effective -external-url: explicit value, else derived from ingress. */}}
{{- define "certcenter.externalUrl" -}}
{{- if .Values.externalUrl -}}
{{- .Values.externalUrl -}}
{{- else if .Values.ingress.enabled -}}
{{- $scheme := ternary "https" "http" (gt (len .Values.ingress.tls) 0) -}}
{{- printf "%s://%s" $scheme .Values.ingress.host -}}
{{- end -}}
{{- end -}}

{{/* config.toml rendered from values. */}}
{{- define "certcenter.configToml" -}}
[server]
host = "0.0.0.0"
port = {{ .Values.service.port }}

[database]
path = "/data/certcenter.db"

[auth]
session_key = {{ required "config.sessionKey is required (openssl rand -hex 32), or set existingSecret" .Values.config.sessionKey | quote }}
username = {{ .Values.config.username | quote }}
password_hash = {{ .Values.config.passwordHash | quote }}

[dns_verification]
skip = {{ .Values.config.dnsVerification.skip | default false }}
{{- with .Values.config.dnsVerification.dohServer }}
doh_server = {{ . | quote }}
{{- end }}
{{- if hasKey .Values.config.dnsVerification "maxRetries" }}
max_retries = {{ .Values.config.dnsVerification.maxRetries }}
{{- end }}
{{- with .Values.config.bus }}
{{- if .url }}

[bus]
url = {{ .url | quote }}
service_id = {{ .serviceId | default "certcenter" | quote }}
token = {{ .token | default "" | quote }}
{{- with .managementUrl }}
management_url = {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.config.extra }}

{{ . }}
{{- end }}
{{- end -}}
