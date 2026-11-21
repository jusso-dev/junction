// Custom table, data collection endpoint (DCE) and data collection rule (DCR)
// for `junction check run --push-sentinel`. Deploy into the resource group that
// holds the Log Analytics workspace (the table is a child of the workspace).
//
// API versions used:
//   Microsoft.OperationalInsights/workspaces@2022-10-01 (existing)
//   Microsoft.OperationalInsights/workspaces/tables@2022-10-01
//   Microsoft.Insights/dataCollectionEndpoints@2022-06-01
//   Microsoft.Insights/dataCollectionRules@2022-06-01
//   Microsoft.Authorization/roleAssignments@2022-04-01

@description('Resource id of the Log Analytics workspace (Sentinel-enabled) that receives the results.')
param workspaceResourceId string

@description('Region for the DCE and DCR. Must be the workspace region.')
param location string = resourceGroup().location

@description('Name of the data collection endpoint.')
param dceName string = 'junction-check-dce'

@description('Name of the data collection rule.')
param dcrName string = 'junction-check-dcr'

@description('Retention for JunctionCheck_CL in days.')
@minValue(4)
@maxValue(730)
param retentionInDays int = 90

@description('Optional object id of the identity that runs `junction check`. When set, it is granted Monitoring Metrics Publisher on the DCR only.')
param pusherPrincipalId string = ''

var tableName = 'JunctionCheck_CL'
var streamName = 'Custom-JunctionCheck_CL'
// Monitoring Metrics Publisher (built-in role).
var monitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

// Row columns sent by junction-check (crates/junction-check/src/push.rs).
// TenantId is reserved by Log Analytics, so the assessed tenant is EntraTenantId.
var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'RunId', type: 'string' }
  { name: 'EntraTenantId', type: 'string' }
  { name: 'TenantLabel', type: 'string' }
  { name: 'CheckId', type: 'string' }
  { name: 'Pack', type: 'string' }
  { name: 'Status', type: 'string' }
  { name: 'Severity', type: 'string' }
  { name: 'Score', type: 'real' }
  { name: 'PackScore', type: 'real' }
  { name: 'Tags', type: 'dynamic' }
  { name: 'Summary', type: 'string' }
  { name: 'Attested', type: 'boolean' }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: last(split(workspaceResourceId, '/'))
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    schema: {
      name: tableName
      columns: columns
    }
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dcrName
  location: location
  dependsOn: [
    table
  ]
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': {
        columns: columns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'workspace'
          workspaceResourceId: workspaceResourceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          streamName
        ]
        destinations: [
          'workspace'
        ]
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
}

resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(pusherPrincipalId)) {
  name: guid(dcr.id, pusherPrincipalId, monitoringMetricsPublisher)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisher)
    principalId: pusherPrincipalId
  }
}

@description('Pass as --dce.')
output logsIngestionEndpoint string = dce.properties.logsIngestion.endpoint

@description('Pass as --dcr.')
output dcrImmutableId string = dcr.properties.immutableId

@description('Pass as --stream.')
output stream string = streamName
