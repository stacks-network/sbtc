#!/bin/sh
set +x

# ------------------------------------
# [1] Create Stacks node config file
# ------------------------------------

# If the miner key is not passed into the process, then we default to not running a Stacks miner
if [[ -z "${MINER_KEY}" ]]; then
    # In the case where we don't see any miner key being passed in, we don't include the `[miner]`section
    sudo bash -c "cat <<EOF> ./config.toml
    [node]
    rpc_bind = "0.0.0.0:20443"
    p2p_bind = "0.0.0.0:20444"
    local_peer_seed = "$LOCAL_PEER_SEED" # Change to any 64-character hexidecimal string
    prometheus_bind = "0.0.0.0:9153"
    working_dir = "$STACKS_WORKING_DIR" # Change to data directory you would like to use for your node
    wait_time_for_microblocks = 0
    mine_microblocks = false
    stacker = true # required if you are running a signer

    [connection_options]
    block_proposal_token = "$MY_HTTP_AUTH_TOKEN"

    [[events_observer]]
    endpoint = "$SINGER_ENDPOINT" # change to your signer endpoint
    retry_count = 255
    include_data_events = false
    events_keys = ["stackerdb", "block_proposal"]

    [burnchain]
    chain = "bitcoin"
    mode = "xenon"
    magic_bytes = "N3"
    pox_prepare_length = 5
    pox_reward_length = 20
    peer_host = "bitcoind.testnet.stacks.co"
    username = "blockstack"
    password = "blockstacksystem"
    burnchain_op_tx_fee = 5500
    commit_anchor_block_within = 300000
    rpc_port = 18332
    peer_port = 18333
    satoshis_per_byte = 20
    first_burn_block_height = 2583232
    first_burn_block_timestamp = 1711238511
    first_burn_block_hash = "000000000000db6864215e5f52067f6418884560a205cb990d13acc350743aaf"

    [[burnchain.epochs]]
    epoch_name = "1.0"
    start_height = 0

    [[burnchain.epochs]]
    epoch_name = "2.0"
    start_height = 2583232

    [[burnchain.epochs]]
    epoch_name = "2.05"
    start_height = 2583245

    [[burnchain.epochs]]
    epoch_name = "2.1"
    start_height = 2583246

    [[burnchain.epochs]]
    epoch_name = "2.2"
    start_height = 2583247

    [[burnchain.epochs]]
    epoch_name = "2.3"
    start_height = 2583248

    [[burnchain.epochs]]
    epoch_name = "2.4"
    start_height = 2583249

    [[burnchain.epochs]]
    epoch_name = "2.5"
    start_height = 2583250

    [[burnchain.epochs]]
    epoch_name = "3.0"
    start_height = 3000000

    [[ustx_balance]]
    address = "ST0DZFQ1XGHC5P1BZ6B7HSWQKQJHM74JBGCSDTNA"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2G2RJR4B5M95D0ZZAGZJP9J4WH090WHP0C5YW0H"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST3JCQJE9NZRCAPPE44Q12KR7FH8AY9HTEMWP2G5F"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "STA0EP5GD8FC661T8Q0Z382QW7Z6JXDM3E476MB7"
    amount = 17500000000000

    [[ustx_balance]]
    address = "ST3MNK12DGQF7JN4Q0STK6926VWE5MN21KJ4EGV0E"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST484MS3VACPAZ90WHC21XQ7T6XANCV341HJYE0W"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2D1M978SCE52GAV07VXSRC9DQBP69X5WHX0DHN5"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2A68NMMXVZDWDTDZ5GJGA69M86V8KK0JS9X1QQP"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2ME1CR5XR0P332SBTSD90P9HG48F1SK8MZVJ3XW"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST19MXV72S9HHRSZCDY10K9DMB11JYPTXVVNYAWPH"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST20Q2N56E1NBWE37R4VGSF89X4HHTB3GSMD8GKYW"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2Q6124HQFKVKPJSS5J6156BJR74FD6EC1297HJ1"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST1114TBQYGNPGFAVXKWBKZAHP0X7ZGX9K6XYYE4F"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST1NCEQ0T4Z32QTYT88BNXJKC9HR3VWYHJ0TB95TP"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "STWF12K119FTA70NDG29MNYWR0CPMF44ZKC2SG2T"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST36G5CRHH1GJVZGFWPTW4H9GSA8VAVWM0ST7AV82"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2KWFMX0SVXFMZ0W7TXZ3MV0C6V276BNAT49XAQW"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST1ZMVDYKGWF5TFGH46GEFBR273JJ3RRTHEDETKNH"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST3D0TEK871ZMBFFF0998YY609A1QGM6ZTYCQJJFQ"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST372ND8K8M3GKESD0KG8ZWJ6EV0GGXWXC5246MJN"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST33PA4H3TW3DQFHG2RXPGGW1FFG5YQJ704B3DA8M"
    amount = 24378281250000

    [[ustx_balance]]
    address = "STJ737JNPK525J86BGSPAW362SRRAYC4SP6F95HC"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST21AJANGK9NA2ZED5D5J1VZPTVW8DY05B0ECMFN"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST30Z74A4S2T8563D844ENSBHBFSVQEVBPV9S0A7E"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2FGTGYAGJVXJZQX17NBJNSQAM4J2V5JFDHEEAZQ"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST16PC3G9BMQH0G37JGAGDGYZPDB5NGNARBDFPWYB"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST1XJHGBSQPV9B14HFYG98ZBSQGKG8GN0AMB3V2VT"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2XDC0R30841X2RRECWV2F9KTANKQEERPS4V3H9D"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2HC6JENRNNE6YVATT7WZVZWVR5J26BGYX67W8G7"
    amount = 24378281250000

    [[ustx_balance]]
    address = "STPW2CGZC98EZ95XYC9DE93SFBS5KA2PYYK89VHM"
    amount = 24378281250000

    [[ustx_balance]]
    address = "STNX3E9MYTA2ZDQK53YNMMJ3E7783DC019JZNYZZ"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST0D135PF2R0S4B6S4G49QZC69KF19MSZ4Z5RDF5"
    amount = 24378281250000
    EOF"

else

    sudo bash -c "cat <<EOF> ./config.toml
    [node]
    rpc_bind = "0.0.0.0:20443"
    p2p_bind = "0.0.0.0:20444"
    local_peer_seed = "$LOCAL_PEER_SEED" # Change to any 64-character hexidecimal string
    prometheus_bind = "0.0.0.0:9153"
    working_dir = "$STACKS_WORKING_DIR" # Change to data directory you would like to use for your node
    wait_time_for_microblocks = 0
    mine_microblocks = false
    stacker = true # required if you are running a signer
    miner = true

    [miner]
    min_tx_fee = 1
    first_attempt_time_ms = 180_000
    subsequent_attempt_time_ms = 360_000
    wait_for_block_download = false
    microblock_attempt_time_ms = 10
    #self_signing_seed = 1
    mining_key = "$MINER_KEY"

    [connection_options]
    block_proposal_token = "$MY_HTTP_AUTH_TOKEN"

    [[events_observer]]
    endpoint = "$SIGNER_ENDPOINT" # change to your signer endpoint
    retry_count = 255
    include_data_events = false
    events_keys = ["stackerdb", "block_proposal"]

    [burnchain]
    chain = "bitcoin"
    mode = "krypton"
    magic_bytes = "T3"
    pox_prepare_length = 5
    pox_reward_length = 20
    peer_host = "bitcoind.testnet.stacks.co"
    username = "blockstack"
    password = "blockstacksystem"
    rpc_port = 18332
    peer_port = 18333
    pox_2_activation = 104

    [[burnchain.epochs]]
    epoch_name = "1.0"
    start_height = 0

    [[burnchain.epochs]]
    epoch_name = "2.0"
    start_height = 0

    [[burnchain.epochs]]
    epoch_name = "2.05"
    start_height = 102

    [[burnchain.epochs]]
    epoch_name = "2.1"
    start_height = 103

    [[burnchain.epochs]]
    epoch_name = "2.2"
    start_height = 105

    [[burnchain.epochs]]
    epoch_name = "2.3"
    start_height = 106

    [[burnchain.epochs]]
    epoch_name = "2.4"
    start_height = 107

    [[burnchain.epochs]]
    epoch_name = "2.5"
    start_height = 108

    [[burnchain.epochs]]
    epoch_name = "3.0"
    start_height = 131

    [[ustx_balance]]
    address = "ST0DZFQ1XGHC5P1BZ6B7HSWQKQJHM74JBGCSDTNA"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2G2RJR4B5M95D0ZZAGZJP9J4WH090WHP0C5YW0H"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST3JCQJE9NZRCAPPE44Q12KR7FH8AY9HTEMWP2G5F"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "STA0EP5GD8FC661T8Q0Z382QW7Z6JXDM3E476MB7"
    amount = 17500000000000

    [[ustx_balance]]
    address = "ST3MNK12DGQF7JN4Q0STK6926VWE5MN21KJ4EGV0E"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST484MS3VACPAZ90WHC21XQ7T6XANCV341HJYE0W"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2D1M978SCE52GAV07VXSRC9DQBP69X5WHX0DHN5"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2A68NMMXVZDWDTDZ5GJGA69M86V8KK0JS9X1QQP"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2ME1CR5XR0P332SBTSD90P9HG48F1SK8MZVJ3XW"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST19MXV72S9HHRSZCDY10K9DMB11JYPTXVVNYAWPH"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST20Q2N56E1NBWE37R4VGSF89X4HHTB3GSMD8GKYW"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST2Q6124HQFKVKPJSS5J6156BJR74FD6EC1297HJ1"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST1114TBQYGNPGFAVXKWBKZAHP0X7ZGX9K6XYYE4F"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "ST1NCEQ0T4Z32QTYT88BNXJKC9HR3VWYHJ0TB95TP"
    amount = 10000000000000000

    [[ustx_balance]]
    address = "STWF12K119FTA70NDG29MNYWR0CPMF44ZKC2SG2T"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST36G5CRHH1GJVZGFWPTW4H9GSA8VAVWM0ST7AV82"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2KWFMX0SVXFMZ0W7TXZ3MV0C6V276BNAT49XAQW"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST1ZMVDYKGWF5TFGH46GEFBR273JJ3RRTHEDETKNH"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST3D0TEK871ZMBFFF0998YY609A1QGM6ZTYCQJJFQ"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST372ND8K8M3GKESD0KG8ZWJ6EV0GGXWXC5246MJN"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST33PA4H3TW3DQFHG2RXPGGW1FFG5YQJ704B3DA8M"
    amount = 24378281250000

    [[ustx_balance]]
    address = "STJ737JNPK525J86BGSPAW362SRRAYC4SP6F95HC"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST21AJANGK9NA2ZED5D5J1VZPTVW8DY05B0ECMFN"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST30Z74A4S2T8563D844ENSBHBFSVQEVBPV9S0A7E"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2FGTGYAGJVXJZQX17NBJNSQAM4J2V5JFDHEEAZQ"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST16PC3G9BMQH0G37JGAGDGYZPDB5NGNARBDFPWYB"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST1XJHGBSQPV9B14HFYG98ZBSQGKG8GN0AMB3V2VT"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2XDC0R30841X2RRECWV2F9KTANKQEERPS4V3H9D"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST2HC6JENRNNE6YVATT7WZVZWVR5J26BGYX67W8G7"
    amount = 24378281250000

    [[ustx_balance]]
    address = "STPW2CGZC98EZ95XYC9DE93SFBS5KA2PYYK89VHM"
    amount = 24378281250000

    [[ustx_balance]]
    address = "STNX3E9MYTA2ZDQK53YNMMJ3E7783DC019JZNYZZ"
    amount = 24378281250000

    [[ustx_balance]]
    address = "ST0D135PF2R0S4B6S4G49QZC69KF19MSZ4Z5RDF5"
    amount = 24378281250000
    EOF"
fi