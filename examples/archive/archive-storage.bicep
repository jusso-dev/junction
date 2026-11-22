// Storage account and container for `junction archive`, with version-level
// immutability so archived objects cannot be changed or deleted before their
// retention ends, even by an account owner.
//
// API versions used:
//   Microsoft.Storage/storageAccounts@2023-05-01
//   Microsoft.Storage/storageAccounts/blobServices@2023-05-01
//   Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01
//   Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01
//   Microsoft.Authorization/roleDefinitions@2022-04-01
//   Microsoft.Authorization/roleAssignments@2022-04-01
//
// Deploy with a deployment identity that can create role definitions. Junction
// itself never creates or changes any of these resources.

@description('Globally unique storage account name (3-24 lower-case letters and digits).')
param storageAccountName string

@description('Region. Pick one that meets your data residency needs, for example australiaeast.')
param location string = resourceGroup().location

@description('Container that holds the archive.')
param containerName string = 'junction-archive'

@description('Default retention for every archived object, in days. 365 is the Junction default.')
@minValue(1)
@maxValue(146000)
param retentionDays int = 365

@description('Object id of the collector identity. Granted create-and-read only.')
param collectorPrincipalId string = ''

@description('Object id of the searcher identity. Granted Storage Blob Data Reader.')
param searcherPrincipalId string = ''

@description('Object id of the hold administrator. Granted Storage Blob Data Contributor, which Set Blob Legal Hold needs.')
param holdAdminPrincipalId string = ''

// Built-in role ids.
var blobDataReader = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var blobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_ZRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Cool'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      // Tighten to your collector's network (selected networks or a private endpoint).
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
    // Version-level immutability needs blob versioning on the account.
    immutableStorageWithVersioning: {
      enabled: true
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: {
      enabled: true
    }
  }
}

// Default time-based retention for every blob version in the container.
resource policy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: container
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
}

// Create and read only: no write (overwrite), no delete, no immutability actions.
resource collectorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (!empty(collectorPrincipalId)) {
  name: guid(account.id, 'junction-archive-collector')
  properties: {
    roleName: 'Junction Archive Collector (${storageAccountName})'
    description: 'Create new blobs and read them back. Cannot overwrite or delete.'
    assignableScopes: [
      account.id
    ]
    permissions: [
      {
        actions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'
        ]
      }
    ]
  }
}

resource collectorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(collectorPrincipalId)) {
  name: guid(container.id, collectorPrincipalId, 'collector')
  scope: container
  properties: {
    roleDefinitionId: collectorRole.id
    principalId: collectorPrincipalId
  }
}

resource searcherAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(searcherPrincipalId)) {
  name: guid(container.id, searcherPrincipalId, blobDataReader)
  scope: container
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataReader)
    principalId: searcherPrincipalId
  }
}

resource holdAdminAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(holdAdminPrincipalId)) {
  name: guid(container.id, holdAdminPrincipalId, blobDataContributor)
  scope: container
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataContributor)
    principalId: holdAdminPrincipalId
  }
}

@description('Use as account_url in the archive configuration.')
output accountUrl string = account.properties.primaryEndpoints.blob

@description('Use as container in the archive configuration.')
output container string = containerName

@description('Run once testing is complete to lock the policy. A locked policy can only be extended, never shortened or removed.')
output lockCommand string = 'az storage container immutability-policy lock --resource-group ${resourceGroup().name} --account-name ${storageAccountName} --container-name ${containerName} --if-match <etag from az storage container immutability-policy show>'
