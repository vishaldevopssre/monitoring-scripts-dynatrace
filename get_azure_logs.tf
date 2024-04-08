variable "forwarderName" {
  type        = string
  description = "Dynatrace log forwarder name"
  default     = "dynatracelogs"
}

variable "targetUrl" {
  type        = string
  description = "Dynatrace destination (ActiveGate) URL"
}

variable "targetPaasToken" {
  type        = string
  description = "Dynatrace PaaS token"
  sensitive   = true
  default     = "dummyToken"
}

variable "targetAPIToken" {
  type        = string
  description = "Dynatrace API token"
  sensitive   = true
}

variable "eventHubConnectionString" {
  type        = string
  description = "Event hub connection string"
  default     = ""
}

variable "deployActiveGateContainer" {
  type        = bool
  description = "Deploy ActiveGate"
  default     = false
}

variable "selfMonitoringEnabled" {
  type        = bool
  description = "Send self-monitoring metrics to Azure? (true/false)"
  default     = false
}

variable "requireValidCertificate" {
  type        = bool
  description = "Verify Dynatrace log ingest endpoint SSL certificate? (true/false)"
  default     = false
}

variable "filterConfig" {
  type        = string
  description = "Filter config"
  default     = ""
}

variable "eventhubConnectionClientId" {
  type        = string
  description = "MI user id"
  default     = ""
}

variable "eventhubConnectionCredentials" {
  type        = string
  description = "Managed Identity"
  default     = ""
}

variable "eventhubConnectionFullyQualifiedNamespace" {
  type        = string
  description = "Eventhub's host name"
  default     = ""
}

locals {
  resourceGroupName = "${var.forwarderName}${random_string.random_id.result}-resource-group"
  eventHubNamespace = "${local.forwarderNameShort}${random_string.random_id.result}"
  eventHubName = "${var.forwarderName}${random_string.random_id.result}-ehub"
  eventHubNamespaceAuthRule = "${var.forwarderName}${random_string.random_id.result}-ehubns-auth-rule"

  dtHost = var.targetUrl
  dtHostParts = split("/", var.targetUrl)
  registryUser = can(index(local.dtHostParts, 2)) ? index(local.dtHostParts, 2) : split(".", local.dtHostParts[0])[0]

  image           = "${local.dtHost}/linux/activegate:latest"
  networkProfileName = "${var.forwarderName}${random_string.random_id.result}networkProfile"
  virtualNetworkName = "${var.forwarderName}${random_string.random_id.result}-vnet"
  functionSubnetName = "functionapp"
  containerSubnetName = "aci"
  appServicePlan   = "${var.forwarderName}${random_string.random_id.result}-plan"
  functionName     = "${var.forwarderName}${random_string.random_id.result}-function"
  forwarderNameShort = substr(var.forwarderName, 0, 18)
  storageAccountName = "${local.forwarderNameShort}${random_string.random_id.result}sa"
}

resource "random_string" "random_id" {
  length  = 4
  special = false
  upper   = false
}

# ######################################################################################
# PREREQ
# ######################################################################################

resource "azurerm_resource_group" "rg" {
  name     = local.resourceGroupName
  location = "East US"
}

resource "azurerm_eventhub_namespace" "ehubns" {
  name                = local.eventHubNamespace
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Basic"
  capacity            = 2

  tags = {
    LogsForwarderDeployment = var.forwarderName
  }
}

resource "azurerm_eventhub" "ehub" {
  name                = local.eventHubName
  namespace_name      = azurerm_eventhub_namespace.ehubns.name
  resource_group_name = azurerm_resource_group.rg.name
  partition_count     = 2
  message_retention   = 1
}

resource "azurerm_eventhub_namespace_authorization_rule" "ehubnsauthrule" {
  name                = local.eventHubNamespaceAuthRule
  namespace_name      = azurerm_eventhub_namespace.ehubns.name
  resource_group_name = azurerm_eventhub_namespace.ehubns.resource_group_name
  listen              = true
  send                = false
  manage              = false
}

# ######################################################################################
# dynatrace-azure-forwarder.json
# ######################################################################################

resource "azurerm_virtual_network" "vnet" {
  count              = var.deployActiveGateContainer ? 1 : 0
  name                = local.virtualNetworkName
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["172.0.0.0/22"]

  tags = {
    LogsForwarderDeployment = var.forwarderName
  }
}

resource "azurerm_subnet" "function_subnet" {
  count              = var.deployActiveGateContainer ? 1 : 0
  name               = "functionapp"
  resource_group_name = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet[0].name
  address_prefixes   = ["172.0.1.0/24"]
  service_endpoints = ["Microsoft.Storage"]

  delegation {
    name            = "app-service-delegation"
    service_delegation {
      name = "Microsoft.Web/serverFarms"
    }
  }
}

resource "azurerm_subnet" "container_subnet" {
  count              = var.deployActiveGateContainer ? 1 : 0
  name               = "aci"
  resource_group_name = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet[0].name
  address_prefixes   = ["172.0.0.0/24"]

  delegation {
    name            = "private-subnet-delegation"
    service_delegation {
      name = "Microsoft.ContainerInstance/containerGroups"
    }
  }
}

resource "azurerm_network_profile" "network_profile" {
  count              = var.deployActiveGateContainer ? 1 : 0
  name               = local.networkProfileName
  location = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  container_network_interface {
    name = "eth0"

    ip_configuration {
      name   = "ipconfigprofile1"
      subnet_id = azurerm_subnet.container_subnet[0].id
    }
  }

  tags = {
    LogsForwarderDeployment = var.forwarderName
  }
}

data "azurerm_subscription" "current" {
}

resource "azurerm_container_group" "container_group" {
  count              = var.deployActiveGateContainer ? 1 : 0
  name               = var.forwarderName
  location           = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  sku = "Standard"

  subnet_ids = [azurerm_subnet.container_subnet[0].id]

  container {
    name   = var.forwarderName
    image  = local.image

    cpu = 1
    memory = 1

    ports {
      port     = 9999
      protocol = "TCP"
    }

    environment_variables = {
      DT_CAPABILITIES        = "log_analytics_collector"
      DT_ID_SKIP_HOSTNAME    = "true"
      DT_ID_SEED_SUBSCRIPTIONID  = data.azurerm_subscription.current.id
      DT_ID_SEED_RESOURCEGROUP  = azurerm_resource_group.rg.name
      DT_ID_SEED_RESOURCENAME   = var.forwarderName
    }
  }

  image_registry_credential {
    server   = local.dtHost
    username = local.registryUser
    password = var.targetPaasToken
  }

  restart_policy = "Always"
  os_type        = "Linux"

  tags = {
    LogsForwarderDeployment = var.forwarderName
  }
}

resource "azurerm_storage_account" "storage_account" {
  name                     = local.storageAccountName
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Allow"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = var.deployActiveGateContainer ? [azurerm_subnet.function_subnet[0].id] : []
  }

  min_tls_version = "TLS1_2"
  enable_https_traffic_only = true
  queue_encryption_key_type = "Account"
  table_encryption_key_type = "Account"

  tags = {
    LogsForwarderDeployment = var.forwarderName
  }
}

resource "azurerm_storage_container" "eventhub_container" {
  name                  = "azure-webjobs-eventhub"
  storage_account_name  = azurerm_storage_account.storage_account.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "hosts_container" {
  name                  = "azure-webjobs-hosts"
  storage_account_name  = azurerm_storage_account.storage_account.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "secrets_container" {
  name                  = "azure-webjobs-secrets"
  storage_account_name  = azurerm_storage_account.storage_account.name
  container_access_type = "private"
}

resource "azurerm_service_plan" "app_service_plan" {
  name                = local.appServicePlan
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type = "Linux"
  sku_name = "S1"
}

resource "azurerm_linux_function_app" "function_app" {
  name                = local.functionName
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  storage_account_name = azurerm_storage_account.storage_account.name
  service_plan_id = azurerm_service_plan.app_service_plan.id

  zip_deploy_file = "dynatrace-azure-log-forwarder.zip"

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME      = "python"
    FUNCTIONS_EXTENSION_VERSION   = "~4"
    DYNATRACE_URL                 = var.deployActiveGateContainer ? "https://172.0.0.4:9999/e/${local.registryUser}" : var.targetUrl
    DYNATRACE_ACCESS_KEY          = var.targetAPIToken
    EVENTHUB_CONNECTION_STRING    = azurerm_eventhub_namespace_authorization_rule.ehubnsauthrule.primary_connection_string
    EVENTHUB_NAME                 = local.eventHubName
    AzureWebJobsStorage           = azurerm_storage_account.storage_account.primary_connection_string
    REQUIRE_VALID_CERTIFICATE     = var.requireValidCertificate
    SELF_MONITORING_ENABLED       = var.selfMonitoringEnabled
    RESOURCE_ID                   = local.functionName
    REGION                        = azurerm_resource_group.rg.location
    SCM_DO_BUILD_DURING_DEPLOYMENT = true
    FILTER_CONFIG                 = var.filterConfig
    EVENTHUB_CONNECTION_STRING__clientId                 = var.eventhubConnectionClientId
    EVENTHUB_CONNECTION_STRING__credential               = var.eventhubConnectionCredentials
    EVENTHUB_CONNECTION_STRING__fullyQualifiedNamespace   = var.eventhubConnectionFullyQualifiedNamespace
  }

  site_config {
    always_on = true
    application_stack {
        python_version = "3.8"
    }
  }
}
