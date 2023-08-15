#! /bin/bash
export $(grep -v '^#' .env | xargs)

if [ -z "$REGISTRY_ADDRESS" ]
then
echo "Registry address not specified...."

exit 0
fi
echo "Deploying Wallet Implementation...."

deployment_output_impl=$(forge create --rpc-url $DEPLOYMENT_RPC_URL  \
    --private-key $DEPLOYER_KEY \
    --constructor-args $ENTRYPOINT_ADDRESS \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verify \
    src/wallet/EpochWallet.sol:EpochWallet)
echo "Deployed Wallet Implementation"
# Use grep with regex to find the "Deployed to" line and extract the address
deployed_to_line=$(echo "$deployment_output_impl" | grep -oE 'Deployed to: (0x[0-9a-fA-F]+)')

# Use awk to extract the address from the line
deployed_to_address=$(echo "$deployed_to_line" | awk '{print $3}')

# Print the address (optional)
echo "Impl Deployed to: $deployed_to_address"

echo "Deploying Wallet Factory..."



deployment_output_factory=$(forge create --rpc-url $DEPLOYMENT_RPC_URL  \
    --private-key $DEPLOYER_KEY \
    --constructor-args $deployed_to_address $REGISTRY_ADDRESS \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verify \
    src/wallet/EpochWalletFactory.sol:EpochWalletFactory)


echo "Deployment output: $deployment_output_factory"
# Use grep with regex to find the "Deployed to" line and extract the address
deployed_to_line=$(echo "$deployment_output_factory" | grep -oE 'Deployed to: (0x[0-9a-fA-F]+)')

# Use awk to extract the address from the line
deployed_to_address=$(echo "$deployed_to_line" | awk '{print $3}')

# Print the address (optional)
echo "Factory Deployed to: $deployed_to_address"