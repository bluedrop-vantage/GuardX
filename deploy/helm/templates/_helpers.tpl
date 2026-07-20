{{/*
Common template helpers.
*/}}
{{- define "guardx.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "guardx.labels" -}}
app.kubernetes.io/name: {{ include "guardx.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{/* Resolve an image reference. */}}
{{- define "guardx.image" -}}
{{- $registry := .root.Values.image.registry -}}
{{- $tag := default .root.Values.image.tag .root.Chart.AppVersion -}}
{{- printf "%s/%s:%s" $registry .repo $tag -}}
{{- end -}}
