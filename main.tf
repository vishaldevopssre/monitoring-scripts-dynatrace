locals {
app_data = jsondecode(file("data.json"))
}

resource "dynatrace_management_zone_v2" "mgmz_per_app" {
for_each = local.app_data
name = each.key
rules {
    rule {
    type    = "ME"
    enabled = true
    attribute_rule {
        entity_type           = "HOST"
        host_to_pgpropagation = true
        attribute_conditions {
        condition {
            case_sensitive = true
            key            = "HOST_GROUP_NAME"
            operator       = "EQUALS"
            string_value   = each.value["host-group"]
        }
        }
    }
    }
}
}

resource "dynatrace_alerting" "alerting_per_app" {
for_each = dynatrace_management_zone_v2.mgmz_per_app
name            = each.value.name
management_zone = each.value.legacy_id
rules {
    rule {
    delay_in_minutes = local.app_data[each.value.name]["delay-in-minutes"]
    include_mode     = "NONE"
    severity_level   = "MONITORING_UNAVAILABLE"
}
}
}

resource "dynatrace_email_notification" "email_notification_per_app" {
for_each = dynatrace_alerting.alerting_per_app

name                   = each.value.name
subject                = "{State} Problem {ProblemID}: {ImpactedEntity}"
to                     = local.app_data[each.value.name]["notify"]
body                   = "{ProblemDetailsHTML}"
profile                = each.value.id
active                 = true
notify_closed_problems = true
}
