resource "dynatrace_management_zone_v2" "TerraformExample" {
name = "Terraform Example"
rules {
    rule {
    type    = "ME"
    enabled = true
    attribute_rule {
        entity_type = "WEB_APPLICATION"
        attribute_conditions {
        condition {
            case_sensitive = true
            key            = "WEB_APPLICATION_NAME"
            operator       = "EQUALS"
            string_value   = "easyTravel"
        }
        }
    }
    }
}
}
