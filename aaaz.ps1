# Get all subscriptions
subscriptions=$(az account list --query "[].id" -o tsv)

# Initialize an empty output file
output_file="automation_accounts.csv"
echo "SubscriptionName,AutomationAccountName,ResourceGroupName,IdentityType" > $output_file

# Loop through each subscription
for subscription in $subscriptions; do
  echo "Processing subscription: $subscription"
  
  # Set the subscription context
  az account set --subscription $subscription
  
  # Get all automation accounts in the subscription
  accounts=$(az automation account list --query "[].{Name:name,ResourceGroup:resourceGroup,IdentityType:identity.type}" -o json)

  # Process each automation account
  for account in $(echo "$accounts" | jq -c '.[]'); do
    name=$(echo "$account" | jq -r '.Name')
    resourceGroup=$(echo "$account" | jq -r '.ResourceGroup')
    identityType=$(echo "$account" | jq -r '.IdentityType')

    # Write the results to the CSV file
    echo "$(az account show --query 'name' -o tsv),$name,$resourceGroup,$identityType" >> $output_file
  done
done

echo "Results saved to $output_file"
