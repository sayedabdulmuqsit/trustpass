import { createPublicClient, http, custom, createWalletClient, type Address } from 'viem';
import { sepolia } from 'viem/chains';
import deployedAddresses from '../../ignition/deployments/chain-11155111/deployed_addresses.json';
import IssuerRegistryArtifact from '../../artifacts/contracts/IssuerRegistry.sol/IssuerRegistry.json';
import CredentialAnchorArtifact from '../../artifacts/contracts/CredentialAnchor.sol/CredentialAnchor.json';

export const SEPOLIA_CHAIN_ID = 11155111;
export const SEPOLIA_RPC_URL = 'https://ethereum-sepolia-rpc.publicnode.com';

export const ISSUER_REGISTRY_ADDRESS = deployedAddresses['TrustPassModule#IssuerRegistry'] as Address;
export const CREDENTIAL_ANCHOR_ADDRESS = deployedAddresses['TrustPassModule#CredentialAnchor'] as Address;

export const ISSUER_REGISTRY_ABI = IssuerRegistryArtifact.abi;
export const CREDENTIAL_ANCHOR_ABI = CredentialAnchorArtifact.abi;

// Public client for zero-wallet read queries
export const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(SEPOLIA_RPC_URL),
});

export async function getWalletClient() {
  if (typeof window === 'undefined' || !(window as any).ethereum) {
    throw new Error('MetaMask or Web3 wallet is not installed.');
  }

  const ethereum = (window as any).ethereum;

  // Check and switch network if necessary
  const currentChainId = await ethereum.request({ method: 'eth_chainId' });
  if (parseInt(currentChainId, 16) !== SEPOLIA_CHAIN_ID) {
    try {
      await ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: '0xaa36a7' }], // 11155111 in hex
      });
    } catch (switchError: any) {
      if (switchError.code === 4902) {
        await ethereum.request({
          method: 'wallet_addEthereumChain',
          params: [
            {
              chainId: '0xaa36a7',
              chainName: 'Sepolia',
              nativeCurrency: { name: 'Sepolia Ether', symbol: 'ETH', decimals: 18 },
              rpcUrls: [SEPOLIA_RPC_URL],
              blockExplorerUrls: ['https://sepolia.etherscan.io'],
            },
          ],
        });
      } else {
        throw switchError;
      }
    }
  }

  const [account] = await ethereum.request({ method: 'eth_requestAccounts' });

  return createWalletClient({
    account: account as Address,
    chain: sepolia,
    transport: custom(ethereum),
  });
}
