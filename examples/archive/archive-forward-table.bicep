// Custom table, data collection endpoint (DCE) and data collection rule (DCR)
// for `junction archive forward --to sentinel`. Deploy into the resource group that
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
param dceName string = 'junction-archive-dce'

@description('Name of the data collection rule.')
param dcrName string = 'junction-archive-dcr'

@description('Retention for JunctionArchive_CL in days. The archive itself keeps the full records; this table holds forwarded summaries.')
@minValue(4)
@maxValue(730)
param retentionInDays int = 90

@description('Optional object id of the identity that runs `junction archive forward`. When set, it is granted Monitoring Metrics Publisher on the DCR only.')
param pusherPrincipalId string = ''

var tableName = 'JunctionArchive_CL'
var streamName = 'Custom-JunctionArchive_CL'
// Monitoring Metrics Publisher (built-in role).
var monitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

// Row columns sent by junction-archive (crates/junction-archive/src/forward.rs).
// Redacted summaries only: the actor is a pseudonym and the IP a network.
// TenantId is reserved by Log Analytics, so the archived tenant is EntraTenantId.
var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'RecordId', type: 'string' }
  { name: 'EntraTenantId', type: 'string' }
  { name: 'Source', type: 'string' }
  { name: 'Operation', type: 'string' }
  { name: 'Result', type: 'string' }
  { name: 'ActorPseudonym', type: 'string' }
  { name: 'IpNetwork', type: 'string' }
  { name: 'Rule', type: 'string' }
  { name: 'RuleSeverity', type: 'string' }
  { name: 'SelectorVersion', type: 'string' }
  { name: 'RawSha256', type: 'string' }
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
