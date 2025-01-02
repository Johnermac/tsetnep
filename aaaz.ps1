# Output file
$outputFile = "automation_accounts.csv"
"SubscriptionName,AutomationAccountName,ResourceGroupName,IdentityType" | Out-File -FilePath $outputFile -Encoding utf8

# Get all subscriptions
$subscriptions = az account list --query "[].id" -o tsv

foreach ($subscription in $subscriptions -split "`n") {
    Write-Host "Processing subscription: $subscription" -ForegroundColor Cyan

    # Set subscription context
    az account set --subscription $subscription

    # Get subscription name for output
    $subscriptionName = az account show --query "name" -o tsv

    # Get all automation accounts in the subscription
    $accounts = az automation account list --query "[].{Name:name,ResourceGroup:resourceGroup,IdentityType:identity.type}" -o json | ConvertFrom-Json

    foreach ($account in $accounts) {
        $name = $account.Name
        $resourceGroup = $account.ResourceGroup
        $identityType = if ($account.IdentityType) { $account.IdentityType } else { "None" }

        # Write to CSV
        "$subscriptionName,$name,$resourceGroup,$identityType" | Out-File -Append -FilePath $outputFile -Encoding utf8
    }
}

Write-Host "Results saved to $outputFile" -ForegroundColor Green
