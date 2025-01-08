# Output file
$outputFile = "automation_accounts.csv"
"SubscriptionName,AutomationAccountName,ResourceGroupName,IdentityType" | Out-File -FilePath $outputFile -Encoding utf8

# Get all subscriptions using Azure PowerShell
$subscriptions = Get-AzSubscription

foreach ($subscription in $subscriptions) {
    Write-Host "Processing subscription: $($subscription.Name)" -ForegroundColor Cyan

    # Set subscription context for Azure CLI
    az account set --subscription $subscription.Id

    # Get all Automation Accounts in the subscription
    $accounts = az automation account list --query "[].{Name:name,ResourceGroup:resourceGroup,IdentityType:identity.type}" -o json | ConvertFrom-Json

    foreach ($account in $accounts) {
        $name = $account.Name
        $resourceGroup = $account.ResourceGroup
        $identityType = if ($account.IdentityType) { $account.IdentityType } else { "None" }

        # Write details to CSV
        "$($subscription.Name),$name,$resourceGroup,$identityType" | Out-File -Append -FilePath $outputFile -Encoding utf8
    }
}

Write-Host "Results saved to $outputFile" -ForegroundColor Green


#####

# Output file
$outputFile = "automation_accounts_with_roles.csv"
"SubscriptionName,AutomationAccountName,ResourceGroupName,IdentityType,PrincipalId,RoleAssignments" | Out-File -FilePath $outputFile -Encoding utf8

# Get all subscriptions using Azure PowerShell
$subscriptions = Get-AzSubscription

foreach ($subscription in $subscriptions) {
    Write-Host "Processing subscription: $($subscription.Name)" -ForegroundColor Cyan

    # Set subscription context for Azure CLI
    az account set --subscription $subscription.Id

    # Get all Automation Accounts in the subscription
    $accounts = az automation account list --query "[].{Name:name,ResourceGroup:resourceGroup,IdentityType:identity.type}" -o json | ConvertFrom-Json

    foreach ($account in $accounts) {
        $name = $account.Name
        $resourceGroup = $account.ResourceGroup
        $identityType = if ($account.IdentityType) { $account.IdentityType } else { "None" }

        # Get the principalId for the Automation Account's identity
        $principalId = az automation account show -n $name -g $resourceGroup --query "identity.principalId" -o tsv

        if (-not $principalId) {
            $principalId = "None"
            $roles = "None"
        } else {
            # Get role assignments for the principalId
            $roles = az role assignment list --assignee $principalId --query "[].{Role:roleDefinitionName,Scope:scope}" -o json | ConvertFrom-Json
            $roles = ($roles | ForEach-Object { "$($_.Role) at $($_.Scope)" }) -join "; "
        }

        # Write details to CSV
        "$($subscription.Name),$name,$resourceGroup,$identityType,$principalId,$roles" | Out-File -Append -FilePath $outputFile -Encoding utf8
    }
}

Write-Host "Results saved to $outputFile" -ForegroundColor Green


#policycheck
# Log in to Azure
Connect-AzAccount

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Create an array to store results
$policyResults = @()

foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id

    Write-Host "Processing Subscription: $($subscription.Name)"

    # Get all Policy Assignments in the subscription
    $policyAssignments = Get-AzPolicyAssignment

    foreach ($policyAssignment in $policyAssignments) {
        Write-Host "  Processing Policy Assignment: $($policyAssignment.Name)"

        # Get the policy definition details
        $policyDefinition = Get-AzPolicyDefinition -PolicyDefinitionId $policyAssignment.PolicyDefinitionId

        # Check if the policy is enforcing secure configurations like MFA, encryption
        $isRelevantPolicy = $policyDefinition.Properties.DisplayName -match "MFA|encryption|secure|compliant"

        if ($isRelevantPolicy) {
            $policyResults += [PSCustomObject]@{
                Subscription        = $subscription.Name
                PolicyAssignment    = $policyAssignment.Name
                PolicyDisplayName   = $policyDefinition.Properties.DisplayName
                Scope               = $policyAssignment.Scope
                EnforcementMode     = $policyAssignment.EnforcementMode
            }
        }
    }
}

# Output the results
$policyResults | Format-Table -AutoSize


#non-compliant
# Log in to Azure
Connect-AzAccount

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Create an array to store compliance results
$complianceResults = @()

foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id

    Write-Host "Processing Subscription: $($subscription.Name)"

    # Get all Policy Assignments in the subscription
    $policyAssignments = Get-AzPolicyAssignment

    foreach ($policyAssignment in $policyAssignments) {
        Write-Host "  Processing Policy Assignment: $($policyAssignment.Name)"

        # Get compliance status for the policy assignment
        $compliance = Get-AzPolicyState -PolicyAssignmentId $policyAssignment.PolicyAssignmentId

        foreach ($state in $compliance) {
            if ($state.ComplianceState -ne "Compliant") {
                $complianceResults += [PSCustomObject]@{
                    Subscription      = $subscription.Name
                    PolicyAssignment  = $policyAssignment.Name
                    ResourceId        = $state.ResourceId
                    ComplianceState   = $state.ComplianceState
                }
            }
        }
    }
}

# Output the results
$complianceResults | Format-Table -AutoSize


