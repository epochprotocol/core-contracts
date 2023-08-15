#! /bin/bash
echo "Flattening Contracts"
flatten_output_1=$(forge flatten  --output flattened/EpochWalletFactory.sol src/wallet/EpochWalletFactory.sol)
echo "$flatten_output_1"
flatten_output_2=$(forge flatten  --output flattened/EpochWallet.sol src/wallet/EpochWallet.sol)
echo "$flatten_output_2"
flatten_output_3=$(forge flatten  --output flattened/EpochRegistry.sol src/registry/EpochRegistry.sol)
echo "$flatten_output_3"
