export interface WalletAddress {
  address: string
  publicKey: string
  symbol?: string
  purpose?: string
}

export async function connectWallet(): Promise<WalletAddress[]> {
  const { connect } = await import('@stacks/connect')
  // Xverse's wallet_connect compatibility method does not accept a network parameter.
  // The selected site network is validated against the returned addresses instead.
  const response = await connect()
  return response.addresses
}
