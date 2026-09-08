import { describe, expect, it } from 'vitest'
import {
  SBTC_DEPLOYERS,
  computeDepositAddress,
  findWalletValues,
  normalizeXOnlyPublicKey,
  scriptToAsm,
} from './deposit'

const KEY = '033920f589c2b367400732d2dd61d11b300ad95b2b1bbf008eabcf8cddfee0c12c'
const MAINNET_RECIPIENT = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4'

describe('deposit address computation', () => {
  it('accepts compressed and x-only keys', () => {
    expect(normalizeXOnlyPublicKey(`0x${KEY}`)).toBe(KEY.slice(2))
    expect(normalizeXOnlyPublicKey(KEY.slice(2))).toBe(KEY.slice(2))
  })

  it('builds the same address from a public key and the resulting full script', () => {
    const standard = computeDepositAddress({
      network: 'mainnet',
      recipient: MAINNET_RECIPIENT,
      maxFee: 80_000,
      lockTime: 950,
      reclaimPublicKey: KEY,
      signersPublicKey: KEY,
    })
    const advanced = computeDepositAddress({
      network: 'mainnet',
      recipient: MAINNET_RECIPIENT,
      maxFee: 80_000,
      reclaimScript: standard.reclaimScript,
      signersPublicKey: KEY,
    })
    expect(advanced).toEqual(standard)
    expect(standard.address).toMatch(/^bc1p/)
    expect(scriptToAsm(standard.depositScript)).toMatch(/^OP_PUSHBYTES_\d+ /)
    expect(scriptToAsm(standard.depositScript)).toContain('OP_CHECKSIG')
    expect(scriptToAsm(standard.reclaimScript)).toBe(
      `OP_PUSHBYTES_2 b603 OP_CHECKSEQUENCEVERIFY OP_DROP OP_PUSHBYTES_32 ${KEY.slice(2)} OP_CHECKSIG`,
    )
  })

  it('renders push opcodes and minimally encoded script numbers', () => {
    expect(scriptToAsm('03ffff00b26a')).toBe(
      'OP_PUSHBYTES_3 ffff00 OP_CHECKSEQUENCEVERIFY OP_RETURN',
    )
  })

  it('selects a P2WPKH address rather than a Taproot address', () => {
    expect(
      findWalletValues(
        [
          { symbol: 'BTC', address: `bc1p${'q'.repeat(58)}`, publicKey: KEY },
          {
            symbol: 'BTC',
            purpose: 'payment',
            address: `bc1q${'q'.repeat(38)}`,
            publicKey: KEY,
          },
          { symbol: 'STX', address: MAINNET_RECIPIENT, publicKey: KEY },
        ],
        'mainnet',
      ),
    ).toEqual({ recipient: MAINNET_RECIPIENT, reclaimPublicKey: KEY.slice(2) })
  })

  it('rejects a recipient from the wrong network', () => {
    expect(() =>
      computeDepositAddress({
        network: 'testnet',
        recipient: MAINNET_RECIPIENT,
        maxFee: 80_000,
        lockTime: 950,
        reclaimPublicKey: KEY,
        signersPublicKey: KEY,
      }),
    ).toThrow('Enter a testnet Stacks recipient.')
  })

  it('uses the current testnet sBTC deployer', () => {
    expect(SBTC_DEPLOYERS.testnet).toBe('SN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1')
  })

  it('constructs Stacks testnet deposits on Bitcoin regtest', () => {
    const result = computeDepositAddress({
      network: 'testnet',
      recipient: SBTC_DEPLOYERS.testnet,
      maxFee: 80_000,
      lockTime: 950,
      reclaimPublicKey: KEY,
      signersPublicKey: KEY,
    })
    expect(result.address).toMatch(/^bcrt1p/)
  })
})
