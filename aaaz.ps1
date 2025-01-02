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
