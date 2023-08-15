#! /bin/bash
export $(grep -v '^#' .env | xargs)



echo "Deploying Bytes library...."
deployment_output_library=$(forge create --rpc-url $DEPLOYMENT_RPC_URL  \
    --private-key $DEPLOYER_KEY \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verify \
    ./lib/encoded-data-manipulation-lib/src/ByteManipulationLibrary.sol:ByteManipulationLibrary)
echo "Deployed BytesManipulation Library"
# Use grep with regex to find the "Deployed to" line and extract the address
deployed_to_line_lib=$(echo "$deployment_output_library" | grep -oE 'Deployed to: (0x[0-9a-fA-F]+)')

# Use awk to extract the address from the line
deployed_to_address_lib=$(echo "$deployed_to_line_lib" | awk '{print $3}')
echo "Bytes Library Deployed to address: $deployed_to_address_lib"