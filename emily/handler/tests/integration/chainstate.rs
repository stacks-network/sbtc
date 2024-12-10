use std::cmp::Ordering;

use testing_emily_client::apis;
use testing_emily_client::apis::configuration::Configuration;
use testing_emily_client::models::Chainstate;

use crate::common::clean_setup;
use test_case::test_case;

/// Make a test chainstate.
fn new_test_chainstate(height: u64, fork_id: i32) -> Chainstate {
    Chainstate {
        stacks_block_hash: format!("test-hash-{height}-fork-{fork_id}"),
        stacks_block_height: height,
    }
}

/// An arbitrary fully ordered partial cmp comparator for Chainstate.
/// This is useful for sorting vectors of chainstates so that vectors with
/// the same elements will be considered equal in a test assert.
fn arbitrary_chainstate_partial_cmp(a: &Chainstate, b: &Chainstate) -> Ordering {
    let a_str: String = format!("{}-{}", a.stacks_block_hash, a.stacks_block_height);
    let b_str: String = format!("{}-{}", b.stacks_block_hash, b.stacks_block_height);
    b_str
        .partial_cmp(&a_str)
        .expect("Failed to compare two strings that should be comparable")
}

/// Makes a bunch of chainstates.
async fn batch_set_chainstates(
    configuration: &Configuration,
    create_requests: Vec<Chainstate>,
) -> Vec<Chainstate> {
    let mut created: Vec<Chainstate> = Vec::with_capacity(create_requests.len());
    for request in create_requests {
        created.push(
            apis::chainstate_api::set_chainstate(&configuration, request)
                .await
                .expect("Received an error after making a valid create deposit request api call."),
        );
    }
    created
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(1123, 1128; "create-5-chainstates")]
#[tokio::test]
async fn create_and_get_chainstate_happy_path(min_height: u64, max_height: u64) {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let mut expected_chainstates: Vec<Chainstate> = (min_height..max_height + 1)
        .map(|height| new_test_chainstate(height, 0))
        .collect();

    let expected_chaintip = new_test_chainstate(max_height, 0);

    // Act.
    // --------
    let mut created_chainstates =
        batch_set_chainstates(&configuration, expected_chainstates.clone()).await;

    let mut gotten_chainstates: Vec<Chainstate> = Vec::new();
    for chainstate in expected_chainstates.iter() {
        let gotten_chainstate = apis::chainstate_api::get_chainstate_at_height(
            &configuration,
            chainstate.stacks_block_height,
        )
        .await
        .expect("Received an error after making a valid get chainstate at height api call.");
        gotten_chainstates.push(gotten_chainstate);
    }

    let gotten_chaintip = apis::chainstate_api::get_chain_tip(&configuration)
        .await
        .expect("Received an error after making a valid set chaintip api call.");

    // Assert.
    // --------
    expected_chainstates.sort_by(arbitrary_chainstate_partial_cmp);
    created_chainstates.sort_by(arbitrary_chainstate_partial_cmp);
    gotten_chainstates.sort_by(arbitrary_chainstate_partial_cmp);
    assert_eq!(expected_chainstates, created_chainstates);
    assert_eq!(expected_chainstates, gotten_chainstates);
    assert_eq!(expected_chaintip, gotten_chaintip)
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(1123, 1128, 1133; "standard-reorg")]
#[test_case(1123, 1133, 1133; "reorg-to-tip-at-same-height")]
#[test_case(1123, 1111, 1133; "reorg-to-tip-below-any-existing-entry")]
#[tokio::test]
async fn create_and_get_chainstate_reorg_happy_path(
    min_height: u64,
    reorg_height: u64,
    max_height: u64,
) {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let original_chainstates: Vec<Chainstate> = (min_height..max_height + 1)
        .map(|height| new_test_chainstate(height, 0))
        .collect();

    let expected_post_reorg_chaintip = new_test_chainstate(reorg_height, 1);

    // Act.
    // --------
    batch_set_chainstates(&configuration, original_chainstates.clone()).await;

    let created_reorged_chainstate =
        apis::chainstate_api::set_chainstate(&configuration, expected_post_reorg_chaintip.clone())
            .await
            .expect("Received an error after making a valid set chainstate api call.");

    let gotten_post_reorg_chaintip = apis::chainstate_api::get_chain_tip(&configuration)
        .await
        .expect("Received an error after making a valid get chaintip api call.");

    // Assert.
    // --------
    assert_eq!(expected_post_reorg_chaintip, created_reorged_chainstate);
    assert_eq!(expected_post_reorg_chaintip, gotten_post_reorg_chaintip);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(1123, 1128; "replay-5-chainstates-out-of-order")]
#[tokio::test]
async fn create_and_replay_does_not_initiate_reorg(min_height: u64, max_height: u64) {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let mut expected_chainstates: Vec<Chainstate> = (min_height..max_height + 1)
        .map(|height| new_test_chainstate(height, 0))
        .collect();

    let expected_chaintip = new_test_chainstate(max_height, 0);

    // Act.
    // --------
    // Make original chainstates.
    batch_set_chainstates(&configuration, expected_chainstates.clone()).await;

    // reverse the order of the chainstates then attempt to re-emplace.
    // In a bad world this makes a bunch of reorgs.
    expected_chainstates.reverse();
    let mut created_chainstates =
        batch_set_chainstates(&configuration, expected_chainstates.clone()).await;

    // reverse back.
    expected_chainstates.reverse();

    let mut gotten_chainstates: Vec<Chainstate> = Vec::new();
    for chainstate in expected_chainstates.iter() {
        let gotten_chainstate = apis::chainstate_api::get_chainstate_at_height(
            &configuration,
            chainstate.stacks_block_height,
        )
        .await
        .expect("Received an error after making a valid get chainstate at height api call.");
        gotten_chainstates.push(gotten_chainstate);
    }

    let gotten_chaintip = apis::chainstate_api::get_chain_tip(&configuration)
        .await
        .expect("Received an error after making a valid set chaintip api call.");

    // Assert.
    // --------
    expected_chainstates.sort_by(arbitrary_chainstate_partial_cmp);
    created_chainstates.sort_by(arbitrary_chainstate_partial_cmp);
    gotten_chainstates.sort_by(arbitrary_chainstate_partial_cmp);
    assert_eq!(expected_chainstates, created_chainstates);
    assert_eq!(expected_chainstates, gotten_chainstates);
    assert_eq!(expected_chaintip, gotten_chaintip)
}
