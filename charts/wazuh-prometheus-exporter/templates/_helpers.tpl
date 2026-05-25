{{/* Expand the name of the chart. */}}
{{- define "wazuh-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "wazuh-exporter.fullname" -}}
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

{{- define "wazuh-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "wazuh-exporter.labels" -}}
helm.sh/chart: {{ include "wazuh-exporter.chart" . }}
{{ include "wazuh-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "wazuh-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wazuh-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "wazuh-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "wazuh-exporter.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image ref; tag falls back to the chart appVersion. */}}
{{- define "wazuh-exporter.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Name of the Secret holding the API password (existing or chart-created). */}}
{{- define "wazuh-exporter.passwordSecretName" -}}
{{- if .Values.wazuh.existingSecret -}}
{{- .Values.wazuh.existingSecret -}}
{{- else -}}
{{- include "wazuh-exporter.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "wazuh-exporter.passwordSecretKey" -}}
{{- if .Values.wazuh.existingSecret -}}
{{- .Values.wazuh.existingSecretKey -}}
{{- else -}}
password
{{- end -}}
{{- end -}}

{{/* Whether the API password is configured at all (enables the password env + collectors). */}}
{{- define "wazuh-exporter.hasPassword" -}}
{{- if or .Values.wazuh.existingSecret .Values.wazuh.password -}}true{{- end -}}
{{- end -}}
