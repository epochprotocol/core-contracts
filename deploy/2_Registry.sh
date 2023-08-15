#! /bin/bash
export $(grep -v '^#' .env | xargs)

if [ -z "$REGISTRY_ADDRESS" ]
then
echo "Bytes Library address not specified...."

exit 0
fi

echo "Deploying Registry...."
    # --verify \
    # --etherscan-api-key $ETHERSCAN_API_KEY \
deployment_output_registry=$(forge create --rpc-url $DEPLOYMENT_RPC_URL  \
    --private-key $DEPLOYER_KEY \
    --libraries lib/encoded-data-manipulation-lib/src/ByteManipulationLibrary.sol:ByteManipulationLibrary:$REGISTRY_ADDRESS \
    src/registry/EpochRegistry.sol:EpochRegistry)
echo "Deployed EpochRegistry"
# Use grep with regex to find the "Deployed to" line and extract the address
deployed_to_line=$(echo "$deployment_output_registry" | grep -oE 'Deployed to: (0x[0-9a-fA-F]+)')

# Use awk to extract the address from the line
deployed_to_address=$(echo "$deployed_to_line" | awk '{print $3}')

verification_output=$(forge verify-contract $deployed_to_address src/registry/EpochRegistry.sol:EpochRegistry \
    --num-of-optimizations 200 \
    --watch \
    --chain-id $CHAIN_ID \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --libraries lib/encoded-data-manipulation-lib/src/ByteManipulationLibrary.sol:ByteManipulationLibrary:$REGISTRY_ADDRESS)

# Print the address (optional)
echo "Registry Deployed to address: $deployed_to_address"

