$version: "2.0"

namespace stacks.sbtc

enum OpStatus {
  PENDING
  ACCEPTED
  CONFIRMED
  FAILED
}

string BitcoinTxid
string StacksTxid
string BitcoinBlockHash
integer Satoshis

// Pattern taken from Gumbo's Stack Overflow answer: https://stackoverflow.com/a/475217
@pattern("^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$")
string Base64EncodedBinary

structure Fulfillment {
  bitcoinTxid: String
  bitcoinTxIndex: Integer
  txid: String
  bitcoinBlockHash: String
  bitcoinBlockHeight: Integer
  btcFee: Satoshis
}
