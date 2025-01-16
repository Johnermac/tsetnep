### public storage accounts 

# Path to the text file containing the list of subscription IDs (one ID per line)
$subscriptionFile = "C:\path\to\subscriptions.txt"

# Read subscription IDs from the file
$subscriptionIds = Get-Content -Path $subscriptionFile

# Array to store results
$results = @()

# Define a timeout in seconds
$timeoutSeconds = 10

# Function to execute a block of code with a timeout
function Execute-WithTimeout {
    param (
        [ScriptBlock]$CodeBlock,
        [int]$TimeoutInSeconds
    )
    $job = Start-Job -ScriptBlock $CodeBlock
    if (Wait-Job -Job $job -Timeout $TimeoutInSeconds) {
        Receive-Job -Job $job
    } else {
        Write-Warning "    Operation timed out after $TimeoutInSeconds seconds."
        Stop-Job -Job $job
    }
    Remove-Job -Job $job
}

# Loop through each subscription ID from the file
foreach ($subscriptionId in $subscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $subscriptionId
        Write-Host "Processing Subscription: $subscriptionId" -ForegroundColor Cyan

        # Get all Storage Accounts in the subscription
        $storageAccounts = Get-AzStorageAccount
        foreach ($storageAccount in $storageAccounts) {
            Write-Host "  Storage Account: $($storageAccount.StorageAccountName)" -ForegroundColor Yellow

            # Get Storage Account Context (required for accessing containers)
            $storageContext = $storageAccount.Context

            # Get all Blob Containers in the Storage Account with timeout handling
            $containers = Execute-WithTimeout -CodeBlock {
                Get-AzStorageContainer -Context $storageContext
            } -TimeoutInSeconds $timeoutSeconds

            # If unable to retrieve containers, log and continue
            if (-not $containers) {
                Write-Host "    Unable to access containers for Storage Account: $($storageAccount.StorageAccountName)" -ForegroundColor Red
                continue
            }

            # Process each container
            foreach ($container in $containers) {
                Write-Host "    Checking Container: $($container.Name)" -ForegroundColor Green

                # Check if the container is public
                $publicAccess = $container.PublicAccess
                if ($publicAccess -eq "Blob" -or $publicAccess -eq "Container") {
                    Write-Host "      Public Container Found: $($container.Name)" -ForegroundColor Red

                    # Construct the public URL
                    $publicUrl = "https://$($storageAccount.StorageAccountName).blob.core.windows.net/$($container.Name)"

                    # Add public container details to results
                    $results += [PSCustomObject]@{
                        SubscriptionId   = $subscriptionId
                        StorageAccount   = $storageAccount.StorageAccountName
                        ResourceGroup    = $storageAccount.ResourceGroupName
                        Container        = $container.Name
                        PublicAccess     = $publicAccess
                        PublicURL        = $publicUrl
                    }
                }
            }
        }
    } catch {
        Write-Host "Failed to process subscription: $subscriptionId. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Output the results
$results | Format-Table -AutoSize

# Save results to a CSV file for review
$results | Export-Csv -Path "PublicStorageAccounts.csv" -NoTypeInformation







# ----------------------------------------

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
# Function to check and renew the token if necessary
function Check-Token {
    try {
        Get-AzContext | Out-Null
    } catch {
        Write-Host "Token expired or invalid. Renewing token..."
        Connect-AzAccount -UseDeviceAuthentication | Out-Null
        Write-Host "Token renewed successfully. Continuing..."
    }
}

# Function to execute actions with retry logic
function Execute-WithRetry {
    param (
        [ScriptBlock]$Action,
        [int]$MaxRetries = 3
    )
    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            & $Action
            return
        } catch {
            $retryCount++
            Write-Warning "Error encountered: $_. Attempt $retryCount of $MaxRetries..."
            Start-Sleep -Seconds 5 # Wait before retrying
        }
    }
    Write-Error "Operation failed after $MaxRetries attempts."
}

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Create an array to store compliance results
$complianceResults = @()

foreach ($subscription in $subscriptions) {
    Check-Token

    Execute-WithRetry -Action {
        Set-AzContext -SubscriptionId $subscription.Id
    }

    Write-Host "Processing Subscription: $($subscription.Name)"

    Execute-WithRetry -Action {
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
}

# Output the results
$complianceResults | Format-Table -AutoSize

# Optional: Export results to CSV
$complianceResults | Export-Csv -Path "NonCompliantPolicies.csv" -NoTypeInformation


#---------------

# Authenticate and list all subscriptions
$subscriptions = Get-AzSubscription | ? {$_.State -eq "Enabled"}

# Array to store results
$results = @()

foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id
    Write-Host "Processing Subscription: $($subscription.Name)" -ForegroundColor Cyan

    # Get all Automation Accounts in the subscription
    $automationAccounts = Get-AzAutomationAccount
    foreach ($automationAccount in $automationAccounts) {
        Write-Host "  Automation Account: $($automationAccount.AutomationAccountName)" -ForegroundColor Yellow

        # Check for System-Assigned Managed Identity
        $systemIdentityPrincipalId = $automationAccount.Identity.PrincipalId
        if ($systemIdentityPrincipalId) {
            Write-Host "    System-Assigned Identity: $systemIdentityPrincipalId" -ForegroundColor Green
            $results += [PSCustomObject]@{
                SubscriptionName       = $subscription.Name
                AutomationAccountName  = $automationAccount.AutomationAccountName
                IdentityType           = "System-Assigned"
                PrincipalId            = $systemIdentityPrincipalId
                RunbookName            = $null
                RoleDefinitionName     = $null
                RoleScope              = $null
            }
        }

        # Check for User-Assigned Managed Identities
        $userAssignedIdentities = $automationAccount.Identity.UserAssignedIdentities.Keys
        foreach ($userAssignedIdentityId in $userAssignedIdentities) {
            Write-Host "    User-Assigned Identity: $userAssignedIdentityId" -ForegroundColor Green

            # Extract ResourceGroupName and Name from the User-Assigned Identity ResourceId
            $resourceParts = $userAssignedIdentityId -split "/"
            $resourceGroupName = $resourceParts[-5]
            $identityName = $resourceParts[-1]

            $userAssignedIdentityDetails = Get-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName -Name $identityName
            $results += [PSCustomObject]@{
                SubscriptionName       = $subscription.Name
                AutomationAccountName  = $automationAccount.AutomationAccountName
                IdentityType           = "User-Assigned"
                PrincipalId            = $userAssignedIdentityDetails.PrincipalId
                RunbookName            = $null
                RoleDefinitionName     = $null
                RoleScope              = $null
            }
        }

        # List all Runbooks in the Automation Account
        $runbooks = Get-AzAutomationRunbook -AutomationAccountName $automationAccount.AutomationAccountName -ResourceGroupName $automationAccount.ResourceGroupName
        foreach ($runbook in $runbooks) {
            Write-Host "    Runbook: $($runbook.Name)" -ForegroundColor Magenta

            # Associate Runbook information with each identity
            foreach ($identity in $results | Where-Object { $_.AutomationAccountName -eq $automationAccount.AutomationAccountName }) {
                if (-not $identity.RunbookName) {
                    $identity.RunbookName = $runbook.Name
                }
            }
        }
    }
}

# Retrieve Role Assignments for each Managed Identity
foreach ($identity in $results) {
    if ($identity.PrincipalId) {
        Write-Host "  Checking roles for PrincipalId: $($identity.PrincipalId)" -ForegroundColor Blue
        $roleAssignments = Get-AzRoleAssignment -ObjectId $identity.PrincipalId
        foreach ($roleAssignment in $roleAssignments) {
            $results += [PSCustomObject]@{
                SubscriptionName       = $identity.SubscriptionName
                AutomationAccountName  = $identity.AutomationAccountName
                IdentityType           = $identity.IdentityType
                PrincipalId            = $identity.PrincipalId
                RunbookName            = $identity.RunbookName
                RoleDefinitionName     = $roleAssignment.RoleDefinitionName
                RoleScope              = $roleAssignment.Scope
            }
        }
    }
}

# Output the results
$results | Format-Table -AutoSize

# Save results to a CSV file for further review
$results | Export-Csv -Path "ManagedIdentities_RoleAssignments.csv" -NoTypeInformation



