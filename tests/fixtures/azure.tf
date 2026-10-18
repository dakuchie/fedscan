resource "azurerm_federated_identity_credential" "prod" {
  name                = "gh-prod"
  resource_group_name = "rg"
  parent_id           = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id"
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:acme/app:environment:prod"
  audience            = ["api://AzureADTokenExchange"]
}

# S2: any pull_request run of the repository can obtain the identity.
resource "azurerm_federated_identity_credential" "prs" {
  name                = "gh-prs"
  resource_group_name = "rg"
  parent_id           = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id"
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:acme/app:pull_request"
  audience            = ["api://AzureADTokenExchange"]
}
