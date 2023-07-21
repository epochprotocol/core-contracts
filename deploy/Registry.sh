#! /bin/bash
export $(grep -v '^#' .env | xargs)

echo "Deploying Registry...."

deployment_output_registry=$(forge create --rpc-url $DEPLOYMENT_RPC_URL  \
    --private-key $DEPLOYER_KEY \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verify \
    src/registry/EpochRegistry.sol:EpochRegistry)
echo "Deployed EpochRegistry"
# Use grep with regex to find the "Deployed to" line and extract the address
deployed_to_line=$(echo "$deployment_output_registry" | grep -oE 'Deployed to: (0x[0-9a-fA-F]+)')

# Use awk to extract the address from the line
deployed_to_address=$(echo "$deployed_to_line" | awk '{print $3}')

# Print the address (optional)
echo "Registry Deployed to address: $deployed_to_address"

