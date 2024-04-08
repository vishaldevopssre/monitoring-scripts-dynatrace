export DYNATRACE_ENV_URL=https://########.live.dynatrace.com
export DYNATRACE_API_TOKEN=dt0c01.########.########

./terraform-provider-dynatrace -export

./terraform-provider-dynatrace -export -ref -id

./terraform-provider-dynatrace -export -ref -exclude dynatrace_calculated_service_metric dynatrace_alerting

