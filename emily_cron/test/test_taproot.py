import unittest

from app.utils.taproot import deposit_script_pubkey_hex


class TestDepositScriptPubkey(unittest.TestCase):
    """Verify BIP-341 derivation matches sbtc::deposits::to_script_pubkey."""

    def test_matches_known_mainnet_deposit(self):
        # Scripts and scriptPubKey from emily_cron/test/fixtures/transactions.json
        # (reclaimed_deposit), cross-checked against the Rust sbtc crate.
        deposit_script = (
            "1e000000000001388005168ac681961281d3c932210a3608ce28f0e819831d"
            "7520f898f8a6ddb86dd4608dd168355ec6135fe2839222240c01942e8e7e50dd4c89ac"
        )
        reclaim_script = (
            "60b275207271dd92896e50c81052c4fd1c100a02e656fa3db43807549be345dc42114c84ac"
        )
        expected_spk = "51200a7ef39302e03b8dd9bd44500165adb32fa9ef0ceb75231cb433040dc771c07d"

        self.assertEqual(
            deposit_script_pubkey_hex(deposit_script, reclaim_script),
            expected_spk,
        )


if __name__ == "__main__":
    unittest.main()
