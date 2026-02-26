targetScope = 'subscription'

@description('Policy assignment name')
param assignmentName string

@description('Policy assignment display name')
param displayName string

@description('Policy definition ID')
param policyDefinitionId string

@description('Policy assignment description')
param description string = ''

@description('Parameters for the policy')
param parameters object = {}

@description('Scope for the assignment (subscription or resource group)')
param scope string = subscription().id

@description('Non-compliance message')
param nonComplianceMessage string = 'Resource is not compliant with the security policy'

@description('Managed identity location (for DINE/Modify effects)')
param identityLocation string = ''

resource assignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {
  name: assignmentName
  scope: scope
  identity: identityLocation != '' ? {
    type: 'SystemAssigned'
  } : null
  location: identityLocation != '' ? identityLocation : null
  properties: {
    displayName: displayName
    description: description
    policyDefinitionId: policyDefinitionId
    parameters: parameters
    nonComplianceMessages: [
      {
        message: nonComplianceMessage
      }
    ]
  }
}

output assignmentId string = assignment.id
output identityPrincipalId string = identityLocation != '' ? assignment.identity.principalId : ''
