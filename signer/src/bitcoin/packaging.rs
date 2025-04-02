//! Generic bin-packing functionality

use sbtc::idpack::BitmapSegmenter;
use sbtc::idpack::Segmenter;

use crate::MAX_MEMPOOL_PACKAGE_SIZE;
use crate::MAX_MEMPOOL_PACKAGE_TX_COUNT;

use super::utxo::MAX_BASE_TX_VSIZE;
use super::utxo::OP_RETURN_AVAILABLE_SIZE;

/// The maximum vsize of all items in a package.
///
/// A bitcoin transaction package is a group of one or more transactions
/// where:
/// 1. Each transaction is unconfirmed, and
/// 2. Each transaction has at least one input that is an outpoint from
///    another transaction in the group or each transaction has an output
///    that another transaction in the group spends or the group consists
///    of one transaction.
///
/// This constant is derived from bitcoin core, and has the property that
/// if the packager ensure that the total vsize of the items in the package
/// are under this limit, then the transaction package will be under the
/// bitcoin vsize limit.
const PACKAGE_MAX_VSIZE: u64 =
    ((MAX_MEMPOOL_PACKAGE_SIZE - MAX_MEMPOOL_PACKAGE_TX_COUNT * MAX_BASE_TX_VSIZE) / 5000) * 5000;

/// Package a list of items into optimal bags according to specified
/// constraints.
///
/// This function implements a variant of the Best-Fit-Decreasing bin packing
/// algorithm. Items are sorted by "weight" (votes against) in decreasing order
/// before being placed into optimal bags.
///
/// ## Constraints
///
/// Each bag is subject to the following constraints:
/// 1. The combined votes against cannot exceed `max_votes_against`
/// 2. The number of items requiring signatures cannot exceed
///    `max_needs_signature`
/// 3. Withdrawal IDs must fit within the OP_RETURN size limit (~77 bytes)
/// 4. The total virtual size across all bags must not exceed
///    [`PACKAGE_MAX_VSIZE`]
///
/// ## Parameters
/// - `items`: Collection of items to be packaged
/// - `max_votes_against`: Maximum allowed votes against for any bag
/// - `max_needs_signature`: Maximum number of items requiring signatures in a
///   bag
///
/// ## Notes
/// - Items that exceed constraints individually are silently ignored
///
/// ## Returns
/// An iterator over vectors, where each inner vector represents a bag of
/// compatible items.
pub fn compute_optimal_packages<I, T>(
    items: I,
    max_votes_against: u32,
    max_needs_signature: u16,
) -> impl Iterator<Item = Vec<T>>
where
    I: IntoIterator<Item = T>,
    T: Weighted,
{
    // This is a variant of the Best-Fit-Decreasing algorithm, so we sort
    // by "weight" decreasing. We use the votes against as the weight, but
    // vsize is a reasonable weight metric as well.
    let mut item_vec: Vec<(u32, T)> = items
        .into_iter()
        .map(|item| (item.votes().count_ones(), item))
        .collect();

    item_vec.sort_by_key(|(vote_count, _)| std::cmp::Reverse(*vote_count));

    // Now we just add each item into a bag, and return the
    // collection of bags afterward.
    // Create config and packager
    let config = PackagerConfig::new(max_votes_against, max_needs_signature);
    let mut packager = BestFitPackager::new(config);

    for (_, item) in item_vec {
        packager.insert_item(item);
    }

    packager.finalize()
}

/// A trait for items that can be packaged together according to specific
/// constraints. Used by [`compute_optimal_packages`].
///
/// This trait captures the key properties that determine whether items can be
/// combined in a single Bitcoin transaction:
///
/// 1. How the signers have voted on the request,
/// 2. Whether we are dealing with a deposit or a withdrawal request,
/// 3. The virtual size of the request when included in a sweep transaction.
/// 4. Whether the withdrawal IDs can fit within an OP_RETURN output's
///    size limits.
///
/// This trait has methods that capture all of these factors.
pub trait Weighted {
    /// Whether the item needs a signature or not.
    ///
    /// If a request needs a signature, then including it requires a signing
    /// round and that takes time. Since we try to get all inputs signed well
    /// before the arrival of the next bitcoin block, we cap the number of items
    /// that need a signature.
    ///
    /// ## Returns
    /// `true` if this item will consume one of the limited signature slots in a
    /// bag.
    fn needs_signature(&self) -> bool;

    /// Returns a bitmap where a bit that is set to 1 indicates a signer
    /// voted against this item.
    ///
    /// The combined votes against (using bitwise OR) for all items in a bag
    /// must not exceed the `max_votes_against` threshold.
    ///
    /// ## Returns
    /// A bitmap representing votes against this item.
    fn votes(&self) -> u128;

    /// The virtual size of the item in vbytes. This is supposed to be the
    /// total bitcoin weight of the request once signed on the bitcoin
    /// blockchain.
    ///
    /// For deposits, this is the input UTXO size including witness data.
    /// For withdrawals, this is the entire output vsize.
    ///
    /// ## Returns
    /// The vsize in vbytes.
    fn vsize(&self) -> u64;

    /// The withdrawal ID for this item, if it's a withdrawal request.
    ///
    /// Must return `Some(_)` for withdrawals and `None` otherwise. For
    /// withdrawals, the ID is used to encode a bitmap in the OP_RETURN output.
    ///
    /// ## Returns
    /// `Some(id)` for withdrawals, `None` for other item types.
    fn withdrawal_id(&self) -> Option<u64> {
        None
    }
}

/// Configuration parameters for the bin packing algorithm.
///
/// Defines the constraints applied during the packaging process to ensure
/// transactions are valid according to Bitcoin network rules and sBTC security
/// policies.
#[derive(Debug, Clone, Copy)]
struct PackagerConfig {
    /// Maximum allowed votes against for any bag.
    ///
    /// This limits how many signers can vote against items in a single bag. If
    /// the combined votes against exceeds this threshold, items are placed in
    /// separate bags.
    max_votes_against: u32,
    /// Maximum number of items requiring signatures in a bag.
    ///
    /// Due to performance and timing constraints, we limit the number of items
    /// that need signatures in a single bag.
    max_signatures: u16,
    /// Maximum virtual size for all bags combined.
    ///
    /// Derived from Bitcoin Core's package relay limits to ensure transactions
    /// are accepted by the network.
    max_total_vsize: u64,
    /// Maximum available size for encoding withdrawal IDs in OP_RETURN.
    ///
    /// Enforcement of this limit prevents transaction rejection due to
    /// oversized OP_RETURN outputs.
    max_op_return_size: usize,
}

impl PackagerConfig {
    /// Create a new configuration with the given vote and signature limits.
    ///
    /// ## Parameters
    /// - `max_votes_against`: Maximum allowed votes against for any bag
    /// - `max_signatures`: Maximum number of items requiring signatures in a
    ///   bag
    ///
    /// ## Returns
    /// A new `PackagerConfig` with default values for other constraints.
    fn new(max_votes_against: u32, max_signatures: u16) -> Self {
        Self {
            max_votes_against,
            max_signatures,
            max_total_vsize: PACKAGE_MAX_VSIZE,
            max_op_return_size: OP_RETURN_AVAILABLE_SIZE,
        }
    }
}

/// A container for compatible items that can be packaged together in a Bitcoin
/// transaction.
///
/// Each bag enforces multiple constraints including vote patterns, signature
/// requirements, and withdrawal ID size limits.
///
/// Bags are optimized to group items with similar voting patterns when
/// possible.
#[derive(Debug, Clone)]
struct Bag<T> {
    /// Configuration constraints for this bag
    config: PackagerConfig,
    /// Items contained in this bag
    items: Vec<T>,
    /// Combined votes bitmap (using bitwise OR)
    votes_bitmap: u128,
    /// Count of items requiring signatures
    items_needing_signatures: u16,
    /// Total virtual size of items in this bag
    vsize: u64,
    /// Sorted list of withdrawal IDs in this bag
    withdrawal_ids: Vec<u64>,
}

impl<T> Bag<T>
where
    T: Weighted,
{
    /// Create a new empty bag with the provided configuration.
    ///
    /// ## Parameters
    /// - `config`: Configuration constraints for the bag
    ///
    /// ## Returns
    /// A new empty bag.
    fn new(config: PackagerConfig) -> Self {
        Bag {
            config,
            votes_bitmap: 0,
            items_needing_signatures: 0,
            vsize: 0,
            items: Vec::new(),
            withdrawal_ids: Vec::new(),
        }
    }

    /// Create a new bag from a single item.
    ///
    /// ## Parameters
    /// - `config`: Configuration constraints for the bag
    /// - `item`: Initial item to add to the bag
    ///
    /// ## Returns
    /// A new bag containing the item.
    fn with_item(config: PackagerConfig, item: T) -> Self {
        let mut bag = Self::new(config);
        bag.add_item(item);
        bag
    }

    /// Add an item to the bag.
    ///
    /// Updates internal state including votes, signatures needed, vsize, and
    /// withdrawal IDs.
    ///
    /// ## Parameters
    /// - `item`: Item to add to the bag
    fn add_item(&mut self, item: T) {
        self.votes_bitmap |= item.votes();
        self.items_needing_signatures += item.needs_signature() as u16;
        self.vsize += item.vsize();

        if let Some(id) = item.withdrawal_id() {
            match self.withdrawal_ids.binary_search(&id) {
                Ok(_) => {} // ID already exists, do nothing
                Err(pos) => self.withdrawal_ids.insert(pos, id),
            }
        }

        self.items.push(item);
    }

    /// Check if an item is compatible with this bag according to all
    /// constraints.
    ///
    /// An item is compatible when:
    /// 1. Combined votes against ≤ max_votes_against
    /// 2. Combined signature requirements ≤ max_signatures
    /// 3. Withdrawal ID (if any) fits within remaining OP_RETURN space
    ///
    /// ## Parameters
    /// - `item`: Item to check for compatibility
    ///
    /// ## Returns
    /// `true` if the item can be safely added to this bag.
    fn is_compatible(&self, item: &T) -> bool {
        self.votes_compatible(item)
            && self.signatures_compatible(item)
            && self.withdrawal_id_compatible(item)
    }

    /// Check if an item's votes are compatible with this bag.
    ///
    /// ## Parameters
    /// - `item`: Item to check for vote compatibility
    ///
    /// ## Returns
    /// `true` if the combined votes don't exceed the maximum allowed.
    fn votes_compatible(&self, item: &T) -> bool {
        let combined_votes = self.votes_bitmap | item.votes();
        combined_votes.count_ones() <= self.config.max_votes_against
    }

    /// Check if an item's signature requirement is compatible with this bag.
    ///
    /// ## Parameters
    /// - `item`: Item to check for signature compatibility
    ///
    /// ## Returns
    /// `true` if adding the item wouldn't exceed the signature limit.
    fn signatures_compatible(&self, item: &T) -> bool {
        let sig = item.needs_signature() as u16;
        self.items_needing_signatures + sig <= self.config.max_signatures
    }

    /// Check if an item's withdrawal ID is compatible with this bag.
    ///
    /// ## Parameters
    /// - `item`: Item to check for withdrawal ID compatibility
    ///
    /// ## Returns
    /// `true` if the item's withdrawal ID can fit in this bag's OP_RETURN.
    fn withdrawal_id_compatible(&self, item: &T) -> bool {
        let Some(id) = item.withdrawal_id() else {
            return true;
        };

        self.can_add_withdrawal_id(id)
    }

    /// Calculate compatibility score between item and bag (smaller is better).
    ///
    /// The score is based on how different the vote patterns are (using XOR).
    /// Lower scores indicate items with more similar voting patterns.
    ///
    /// ## Parameters
    /// - `item`: Item to calculate compatibility score for
    ///
    /// ## Returns
    /// A score where lower values indicate better compatibility.
    fn compatibility_score(&self, item: &T) -> u32 {
        // XOR measures how different the vote patterns are
        (self.votes_bitmap ^ item.votes()).count_ones()
    }

    /// Check if adding a single withdrawal ID would exceed the OP_RETURN size
    /// limit.
    ///
    /// ## Parameters
    /// - `new_id`: Withdrawal ID to check
    ///
    /// ## Returns
    /// - `true` if the ID can be added
    /// - `false` if adding the ID would exceed size limits
    ///
    /// ## Implementation Notes
    /// This method simulates adding the new withdrawal ID to the bag's existing
    /// IDs while maintaining sorted order. The [`BitmapSegmenter`] is then used
    /// to estimate the size of the combined IDs, which requires sorted and
    /// de-duplicated IDs.
    fn can_add_withdrawal_id(&self, new_id: u64) -> bool {
        // If no existing IDs then the range is 0, so we can add any ID
        if self.withdrawal_ids.is_empty() {
            return true;
        }

        // Check if ID already exists (would have no effect on size)
        match self.withdrawal_ids.binary_search(&new_id) {
            Ok(_) => true, // ID already in the list
            Err(pos) => {
                // Create combined IDs with new ID inserted at correct position
                let mut combined_ids = Vec::with_capacity(self.withdrawal_ids.len() + 1);
                combined_ids.extend_from_slice(&self.withdrawal_ids[0..pos]);
                combined_ids.push(new_id);
                combined_ids.extend_from_slice(&self.withdrawal_ids[pos..]);

                // Check if the combined IDs fit
                self.can_fit_withdrawal_ids(&combined_ids)
            }
        }
    }

    /// Check if a set of withdrawal IDs can fit within the OP_RETURN size
    /// limit.
    ///
    /// ## Parameters
    /// - `ids`: Collection of withdrawal IDs to check
    ///
    /// ## Returns
    /// - `true` if the IDs will fit within the OP_RETURN size limits.
    /// - `false` if the IDs exceed the size limits, or an error occurs during
    ///    estimation (for example if the id's have become unsorted or contain
    ///    duplicates).
    fn can_fit_withdrawal_ids(&self, ids: &[u64]) -> bool {
        if ids.is_empty() {
            return true;
        }

        BitmapSegmenter
            .estimate_size(ids)
            .map_or_else(
                |error| {
                    tracing::warn!(%error, withdrawal_ids = ?ids, "error estimating packaged withdrawal id size");
                    false
                },
                |size| size <= self.config.max_op_return_size
            )
    }
}

/// Implementation of the Best-Fit bin packing algorithm for compatible items.
///
/// This packager attempts to:
/// 1. Group items with similar voting patterns together
/// 2. Respect signature limits for each bag
/// 3. Ensure withdrawal IDs fit within OP_RETURN size limits
/// 4. Keep total virtual size within Bitcoin network limits
///
/// ## Implementation Notes
/// - Items that exceed individual limits are silently ignored
/// - Items that would cause the total vsize to exceed limits are ignored
#[derive(Debug)]
struct BestFitPackager<T> {
    /// All created bags of compatible items
    bags: Vec<Bag<T>>,
    /// Configuration constraints
    config: PackagerConfig,
    /// Running total of virtual size across all bags
    total_vsize: u64,
}

impl<T: Weighted> BestFitPackager<T> {
    fn new(config: PackagerConfig) -> Self {
        Self {
            bags: Vec::new(),
            config,
            total_vsize: 0,
        }
    }

    /// Find the best bag to insert a new item.
    ///
    /// "Best" is defined as the compatible bag with the lowest compatibility score.
    ///
    /// ## Parameters
    /// - `item`: Item to find a bag for
    ///
    /// ## Returns
    /// A mutable reference to the best bag, or `None` if no compatible bag exists.
    fn find_best_bag(&mut self, item: &T) -> Option<&mut Bag<T>> {
        self.bags
            .iter_mut()
            .filter(|bag| bag.is_compatible(item))
            .min_by_key(|bag| bag.compatibility_score(item))
    }

    /// Try to insert an item into the best-fit bag, or create a new one.
    ///
    /// Items that exceed individual limits or would cause the total vsize to
    /// exceed limits are silently ignored.
    ///
    /// ## Parameters
    /// - `item`: Item to insert
    ///
    /// ## Notes
    /// - This method silently ignores items that exceed individual either
    ///   individual or aggregate limits (i.e. votes-against or total package
    ///   vsize).
    fn insert_item(&mut self, item: T) {
        let votes_against = item.votes().count_ones();
        let total_package_vsize = self.total_vsize + item.vsize();

        // Early exits for items exceeding our bag-independent limits.
        if votes_against > self.config.max_votes_against
            || total_package_vsize > self.config.max_total_vsize
        {
            return;
        }

        // Add to total vsize
        self.total_vsize += item.vsize();

        // Use find_best_bag or create a new bag
        match self.find_best_bag(&item) {
            Some(bag) => bag.add_item(item),
            None => self.bags.push(Bag::with_item(self.config, item)),
        }
    }

    /// Consumes the packager and returns an iterator over the packed item
    /// groups.
    ///
    /// ## Returns
    /// An iterator that yields each bag's contents as a `Vec<T>`, preserving
    /// the original compatibility constraints established during insertion.
    fn finalize(self) -> impl Iterator<Item = Vec<T>> {
        self.bags.into_iter().map(|bag| bag.items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::array::BitArray;
    use bitvec::field::BitField;
    use test_case::test_case;

    impl<T> BestFitPackager<T>
    where
        T: Weighted,
    {
        /// Create a new bag with the given items and add it to the packager.
        fn new_bag(&mut self, items: Vec<T>) -> &mut Bag<T> {
            let bag = Bag::from_items(self.config, items);
            self.bags.push(bag);
            self.bags.last_mut().unwrap()
        }
    }

    impl<T> Bag<T>
    where
        T: Weighted,
    {
        /// Add multiple items to the bag.
        fn add_items(&mut self, items: Vec<T>) {
            for item in items {
                self.add_item(item);
            }
        }

        /// Create a new bag from a collection of items.
        fn from_items(config: PackagerConfig, items: Vec<T>) -> Self {
            let mut bag = Bag {
                config,
                items: Vec::new(),
                votes_bitmap: 0,
                items_needing_signatures: 0,
                vsize: 0,
                withdrawal_ids: Vec::new(),
            };
            bag.add_items(items);
            bag
        }
    }

    #[derive(Debug, Default, Copy, Clone)]
    struct RequestItem {
        // Votes _against_ the request. A `true` value means a vote against.
        votes: [bool; 5],
        /// Whether this request needs a signature.
        needs_signature: bool,
        /// The virtual size of the request.
        vsize: u64,
        /// The withdrawal request ID for this item, if it's a withdrawal.
        withdrawal_id: Option<u64>,
    }

    impl RequestItem {
        /// Create a new request item with no votes against.
        fn no_votes() -> Self {
            Self::default()
        }

        /// Create a new request item with all votes against.
        fn all_votes() -> Self {
            Self {
                votes: [true; 5],
                ..Default::default()
            }
        }

        /// Create a new request item with specific votes against.
        ///
        /// ## Parameters
        /// - `votes`: Collection of signer indices (1-based) who vote against this item
        fn with_votes(votes: &[usize]) -> Self {
            let mut vote_array = [false; 5];
            for &index in votes {
                vote_array[index - 1] = true;
            }

            Self {
                votes: vote_array,
                ..Default::default()
            }
        }

        /// Create a new request item with a single vote against.
        ///
        /// ## Parameters
        /// - `signer`: The signer index (1-based) who votes against this item
        fn with_vote(signer: usize) -> Self {
            let mut votes = [false; 5];
            votes[signer - 1] = true;
            Self { votes, ..Default::default() }
        }

        /// Set the `needs_signature` field to true, indicating that signing
        /// is required for this request.
        fn sig_required(mut self) -> Self {
            self.needs_signature = true;
            self
        }

        /// Sets the withdrawal request ID for this item.
        fn wid(mut self, withdrawal_id: u64) -> Self {
            self.withdrawal_id = Some(withdrawal_id);
            self
        }

        /// Sets the virtual size for this item.
        fn vsize(mut self, vsize: u64) -> Self {
            self.vsize = vsize;
            self
        }
    }

    impl Weighted for RequestItem {
        fn needs_signature(&self) -> bool {
            self.needs_signature
        }

        fn votes(&self) -> u128 {
            let mut votes = BitArray::<[u8; 16]>::ZERO;
            for (index, value) in self.votes.iter().copied().enumerate() {
                votes.set(index, value);
            }
            votes.load()
        }

        fn vsize(&self) -> u64 {
            self.vsize
        }

        fn withdrawal_id(&self) -> Option<u64> {
            self.withdrawal_id
        }
    }

    struct VotesTestCase<const N: usize> {
        /// The item input into `compute_optimal_packages`.
        items: Vec<RequestItem>,
        /// Used when calling `compute_optimal_packages`.
        max_needs_signature: u16,
        /// Used when calling `compute_optimal_packages`.
        max_votes_against: u32,
        /// After calling `compute_optimal_packages` with the `items` here,
        /// `N` is the expected number of bags, and the `usize`s are the
        /// expected number of items in each bag.
        expected_bag_sizes: [usize; N],
        /// After calling `compute_optimal_packages` with the `items` here,
        /// `N` is the expected number of bags, and the `u64`s are the
        /// expected vsizes of each bag.
        expected_bag_vsizes: [u64; N],
    }

    /// Tests the complete bin-packing algorithm across multiple scenarios including:
    /// - No votes against
    /// - Same votes against
    /// - Different votes requiring multiple bags
    /// - Signature limits causing splits
    /// - Size constraints being enforced
    #[test_case(VotesTestCase {
        items: vec![RequestItem::no_votes(); 6],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [6],
        expected_bag_vsizes: [0],
    } ; "no-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::with_vote(5); 6],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [6],
        expected_bag_vsizes: [0],
    } ; "same-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![
            RequestItem::with_vote(5),
            RequestItem::with_vote(5),
            RequestItem::with_vote(4),
            RequestItem::with_vote(4),
            RequestItem::no_votes(),
        ],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [3, 2],
        expected_bag_vsizes: [0, 0],
    } ; "two-different-votes-against-two-packages")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::no_votes().sig_required(); 25],
        max_needs_signature: 10,
        max_votes_against: 1,
        expected_bag_sizes: [10, 10, 5],
        expected_bag_vsizes: [0, 0, 0],
    } ; "splits-when-too-many-required-signatures")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::no_votes().vsize(4000); 25],
        max_needs_signature: 10,
        max_votes_against: 1,
        expected_bag_sizes: [23],
        expected_bag_vsizes: [92000],
    } ; "ignores-when-vsize-exceeds-max")]
    #[test_case(VotesTestCase {
        items: vec![
            RequestItem::with_votes(&[4, 5]),
            RequestItem::with_votes(&[2, 3]),
            RequestItem::with_votes(&[1, 2]),
            RequestItem::with_vote(1),
            RequestItem::with_vote(2),
            RequestItem::with_vote(3),
        ],
        max_needs_signature: 100,
        max_votes_against: 3,
        expected_bag_sizes: [1, 5],
        expected_bag_vsizes: [0, 0],
    } ; "votes-against-placement")]
    fn returns_optimal_placements<const N: usize>(case: VotesTestCase<N>) {
        let ans =
            compute_optimal_packages(case.items, case.max_votes_against, case.max_needs_signature);
        let collection = ans.collect::<Vec<_>>();
        let iter = collection
            .iter()
            .zip(case.expected_bag_sizes)
            .zip(case.expected_bag_vsizes);

        assert_eq!(collection.len(), N);
        for ((bag, expected_size), expected_vsize) in iter {
            assert_eq!(bag.len(), expected_size);
            let package_vsize = bag.iter().map(|item| item.vsize()).sum::<u64>();
            assert_eq!(package_vsize, expected_vsize);

            // Now for the bitcoin requirement
            more_asserts::assert_le!(package_vsize, PACKAGE_MAX_VSIZE);
        }
    }

    /// Tests that the OP_RETURN size estimation correctly identifies both small sets that fit
    /// and large sets that exceed the size limit.
    #[test]
    fn test_can_fit_withdrawal_ids() {
        let config = PackagerConfig::new(1, 10);
        let bag = Bag::<RequestItem>::new(config);

        // Small set should fit
        assert!(bag.can_fit_withdrawal_ids(&[1, 2, 3, 4, 5]));

        // Generate a large set with poor compression characteristics
        // (values spaced far apart won't compress efficiently with bitmap encoding)
        let large_set: Vec<u64> = (0..75).map(|i| i * 1000).collect();
        assert!(!bag.can_fit_withdrawal_ids(&large_set));
    }

    /// Tests that bags correctly collect, sort, and deduplicate withdrawal IDs.
    #[test]
    fn test_bag_collects_withdrawal_ids() {
        // Create a bag with one withdrawal ID
        let config = PackagerConfig::new(1, 10);
        let mut bag = Bag::new(config);
        bag.add_item(RequestItem::no_votes().wid(42));

        assert_eq!(bag.withdrawal_ids.len(), 1);
        assert_eq!(bag.withdrawal_ids[0], 42);

        // Add more IDs in non-sorted order
        bag.add_items(vec![
            RequestItem::no_votes().wid(100),
            RequestItem::no_votes().wid(5), // Smaller than existing IDs
            RequestItem::no_votes().wid(200),
            RequestItem::no_votes().wid(50),
            RequestItem::no_votes(),         // Not a withdrawal
            RequestItem::no_votes().wid(42), // Duplicate ID
        ]);

        // Verify correct number of unique IDs
        assert_eq!(bag.withdrawal_ids.len(), 5);

        // Verify IDs are sorted
        let expected_ids = [5, 42, 50, 100, 200];
        assert_eq!(bag.withdrawal_ids, expected_ids);

        // IDs should already be sorted, so this should work properly
        assert!(bag.can_fit_withdrawal_ids(&bag.withdrawal_ids));
    }

    /// Tests that vote compatibility correctly evaluates different combinations
    /// of votes against the maximum allowed threshold. Verifies both positive
    /// and negative cases.
    #[test_case(&[1], &[], 1 => true; "one_vote_one_max")]
    #[test_case(&[1, 2], &[], 1 => false; "two_votes_one_max")]
    #[test_case(&[1], &[2], 1 => false; "different_votes_exceed_max")]
    #[test_case(&[1], &[1], 1 => true; "same_votes_within_max")]
    #[test_case(&[1, 2], &[1], 2 => true; "combined_unique_votes_at_limit")]
    fn test_votes_compatible(bag_votes: &[usize], item_votes: &[usize], max_votes: u32) -> bool {
        let config = PackagerConfig::new(max_votes, 5);
        let bag = Bag::from_items(config, vec![RequestItem::with_votes(bag_votes).vsize(10)]);
        let item = RequestItem::with_votes(item_votes).vsize(10);
        bag.votes_compatible(&item)
    }

    /// Tests signature requirement compatibility across different scenarios
    /// including:
    /// - No signatures required
    /// - At capacity
    /// - Below capacity
    /// - Exceeding capacity
    #[test_case(0, false, 1 => true; "no_sigs_in_bag_no_sig_required")]
    #[test_case(5, false, 5 => true; "max_sigs_in_bag_no_sig_required")]
    #[test_case(4, true, 5 => true; "under_max_sigs_sig_required")]
    #[test_case(5, true, 5 => false; "at_max_sigs_sig_required")]
    fn test_signatures_compatible(bag_sigs: u16, item_needs_sig: bool, max_sigs: u16) -> bool {
        let config = PackagerConfig::new(2, max_sigs);

        // Create a bag with the specified number of signatures
        let mut bag = Bag::from_items(
            config,
            vec![], // Empty initially
        );

        // Add items requiring signatures to match bag_sigs
        for _ in 0..bag_sigs {
            bag.items_needing_signatures += 1;
        }

        // Create item that may or may not need a signature
        let mut item = RequestItem::no_votes().vsize(10);
        if item_needs_sig {
            item = item.sig_required();
        }

        bag.signatures_compatible(&item)
    }

    /// Tests withdrawal ID compatibility for various scenarios:
    /// - Empty withdrawal ID lists
    /// - Small ID ranges
    /// - IDs within existing ranges
    /// - IDs that exceed OP_RETURN size limits
    #[test_case(vec![], None => true; "no_withdrawal_id")]
    #[test_case(vec![1, 2, 3], Some(4) => true; "compatible_withdrawal_id")]
    #[test_case(vec![], Some(42) => true; "single_withdrawal_id")]
    #[test_case((1..50).collect::<Vec<u64>>(), Some(300) => true; "many_small_ids_compatible")]
    #[test_case(vec![1, 2, 4, 5], Some(3) => true; "new_id_within_existing_range")]
    fn test_withdrawal_id_compatible(bag_ids: Vec<u64>, item_id: Option<u64>) -> bool {
        let config = PackagerConfig::new(2, 5);

        // Create a bag with specified withdrawal IDs
        let mut bag = Bag::new(config);

        // Add withdrawal IDs
        for id in bag_ids {
            bag.withdrawal_ids.push(id);
        }
        bag.withdrawal_ids.sort();

        // Create item with optional withdrawal ID
        let item = match item_id {
            Some(id) => RequestItem::no_votes().wid(id).vsize(10),
            None => RequestItem::no_votes().vsize(10),
        };

        bag.withdrawal_id_compatible(&item)
    }

    /// Test withdrawal id compatibility at the exact OP_RETURN size boundary.
    #[test]
    fn test_withdrawal_id_compatible_at_exact_op_return_boundary() {
        let mut ids: Vec<u64> = Vec::new();
        let mut next_id: u64 = 0;

        // Fill the ID list until we've precisely exceeded the OP_RETURN limit
        while BitmapSegmenter.estimate_size(&ids).unwrap() <= OP_RETURN_AVAILABLE_SIZE {
            ids.push(next_id);
            next_id += 1;
        }

        // At this point ids are just over the limit - remove the last one
        // to get ≤ OP_RETURN_AVAILABLE_SIZE
        ids.pop();

        // Verify that the new size is at/under the limit
        let safe_size = BitmapSegmenter.estimate_size(&ids).unwrap();
        more_asserts::assert_le!(
            safe_size,
            OP_RETURN_AVAILABLE_SIZE,
            "expected safe size to be under the limit"
        );

        // The last ID in the list is now the last safe ID. Remove it so we can
        // do a proper verification below
        let last_safe_id = ids.pop().unwrap();

        // Create the bag with the IDs that are just under the limit
        let config = PackagerConfig::new(2, 5);
        let mut bag = Bag::<RequestItem>::new(config);
        bag.withdrawal_ids = ids;

        // This ID should be compatible
        let last_safe_item = RequestItem::no_votes().wid(last_safe_id);
        assert!(
            bag.withdrawal_id_compatible(&last_safe_item),
            "expected last safe ID to be compatible"
        );
        bag.withdrawal_ids.push(last_safe_id); // Re-add the ID to the bag

        // This ID should push us over the limit (next_id is the first ID that would
        // exceed the limit)
        let too_big_item = RequestItem::no_votes().wid(next_id);
        assert!(
            !bag.is_compatible(&too_big_item),
            "expected too big ID to be incompatible"
        );
    }

    /// Tests the combined compatibility evaluation including votes, signatures,
    /// and withdrawal ID constraints. Ensures all constraints must be satisfied
    /// for an item to be compatible.
    #[test]
    fn test_is_compatible() {
        let config = PackagerConfig::new(2, 5);

        // Create a bag with 1 vote against and 2 signatures needed
        let bag = Bag::from_items(
            config,
            vec![
                RequestItem::with_vote(1).sig_required().vsize(10),
                RequestItem::no_votes().sig_required().vsize(10),
            ],
        );

        // Compatible item (no additional votes against, needs signature)
        assert!(bag.is_compatible(&RequestItem::with_vote(1).sig_required().vsize(10)));

        // Incompatible item (too many votes against)
        assert!(!bag.is_compatible(&RequestItem::with_votes(&[2, 3]).vsize(10)));

        // Incompatible item (too many signatures needed)
        let full_sig_bag = Bag::from_items(
            config,
            vec![RequestItem::no_votes().sig_required().vsize(10); 5],
        );

        // This would make 6 signatures, exceeding our limit of 5
        assert!(!full_sig_bag.is_compatible(&RequestItem::all_votes().sig_required().vsize(10)));
    }

    /// Tests the algorithm's ability to score compatibility between items with
    /// different voting patterns. Lower scores indicate more similar voting
    /// patterns.
    #[test_case(&[1], &[1] => 0; "identical_votes")]
    #[test_case(&[2], &[1] => 2; "two_differences")]
    #[test_case(&[1, 2], &[1] => 1; "one_difference")]
    fn test_compatibility_score(bag_votes: &[usize], item_votes: &[usize]) -> u32 {
        let config = PackagerConfig::new(5, 10);
        let bag = Bag::from_items(config, vec![RequestItem::with_votes(bag_votes).vsize(10)]);
        let item = RequestItem::with_votes(item_votes).vsize(10);
        bag.compatibility_score(&item)
    }

    /// Tests the bin-packing algorithm's ability to find the optimal bag for
    /// placement based on compatibility score and constraints. Includes
    /// withdrawal ID space considerations.
    #[test_case(
        // Simple case - finds first bag (with vote 1)
        vec![RequestItem::with_vote(1)],
        vec![RequestItem::with_vote(2)],
        vec![RequestItem::with_vote(3)],
        RequestItem::with_vote(1),
        Some(0)
        ; "finds_exact_match")]
    #[test_case(
        // Complex case - finds best compatible bag
        vec![RequestItem::with_votes(&[1, 2, 3])],
        vec![RequestItem::with_votes(&[1, 2])],
        vec![RequestItem::with_vote(1)],
        RequestItem::with_vote(1),
        Some(2)
        ; "finds_most_compatible_bag")]
    #[test_case(
        // Incompatible with all bags
        vec![RequestItem::with_vote(1)],
        vec![RequestItem::with_vote(2)],
        vec![RequestItem::with_vote(3)],
        RequestItem::all_votes(),
        None
        ; "incompatible_with_all_bags")]
    #[test_case(
        // Bag 1: Nearly full OP_RETURN (large range of IDs)
        (0..580).map(|id| RequestItem::no_votes().wid(id)).collect(),
        // Bag 2: Has room for more IDs (small range)
        vec![RequestItem::no_votes().wid(100_000), RequestItem::no_votes().wid(100_001)],
        // Bag 3: Nearly full OP_RETURN (different large range)
        (1000..1580).map(|id| RequestItem::no_votes().wid(id)).collect(),
        // Item with ID that fits in bag 2's range
        RequestItem::no_votes().wid(100_010),
        Some(1) // Should select bag 2 (index 1)
        ; "selects_bag_with_room_for_withdrawal_id")]
    fn test_find_best_bag(
        bag1_items: Vec<RequestItem>,
        bag2_items: Vec<RequestItem>,
        bag3_items: Vec<RequestItem>,
        test_item: RequestItem,
        expected_result: Option<usize>,
    ) {
        let config = PackagerConfig::new(2, 5);
        let mut packager = BestFitPackager::<RequestItem>::new(config);

        // Setup bags
        packager.new_bag(bag1_items);
        packager.new_bag(bag2_items);
        packager.new_bag(bag3_items);

        // Extract the index directly using the same logic
        let best_bag_index = packager
            .bags
            .iter()
            .enumerate()
            .filter(|(_, bag)| bag.is_compatible(&test_item))
            .min_by_key(|(_, bag)| bag.compatibility_score(&test_item))
            .map(|(index, _)| index);

        // Verify expected result matches the direct calculation
        assert_eq!(best_bag_index, expected_result);

        // Verify the actual method returns the right bag
        let best_bag = packager.find_best_bag(&test_item);
        assert_eq!(best_bag.is_some(), best_bag_index.is_some());
    }

    /// Tests item insertion logic including:
    /// - Creating new bags
    /// - Adding to existing compatible bags
    /// - Silently ignoring items that exceed limits
    /// - Handling withdrawal ID constraints
    #[test]
    fn test_insert_item() {
        let config = PackagerConfig::new(2, 5);
        let mut packager = BestFitPackager::<RequestItem>::new(config);

        // Add first item - should create a new bag
        packager.insert_item(RequestItem::with_vote(1).vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 1); // +1
        assert_eq!(packager.bags[0].vsize, 10); // 10

        // Add compatible item (same voting, withdrawal) - should go in existing bag
        packager.insert_item(RequestItem::with_vote(1).wid(1).vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 2); // +1
        assert_eq!(packager.bags[0].vsize, 20); // +10

        // Add compatible item (different voting) - should go in existing bag
        // Note: This is compatible because the combined votes (positions 1,2) equal 2,
        // which doesn't exceed our max_votes_against limit of 2
        packager.insert_item(RequestItem::with_votes(&[1, 2]).vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 3); // +1
        assert_eq!(packager.bags[0].vsize, 30); // +10

        // Add item that exceeds vote limit - should be ignored
        packager.insert_item(RequestItem::all_votes().vsize(10));
        assert_eq!(packager.bags.len(), 1); // No change
        assert_eq!(packager.bags[0].items.len(), 3); // No change
        assert_eq!(packager.bags[0].vsize, 30); // No change

        // Add incompatible item (different voting pattern) - should create new bag
        packager.insert_item(RequestItem::with_votes(&[4, 5]).vsize(10));
        assert_eq!(packager.bags.len(), 2); // +1
        assert_eq!(packager.bags[0].items.len(), 3); // (bag 0) No change
        assert_eq!(packager.bags[1].items.len(), 1); // (bag 1) +1
        assert_eq!(packager.bags[0].vsize, 30); // (bag 0) No change
        assert_eq!(packager.bags[1].vsize, 10); // (bag 1) 10

        // Add item that exceeds vsize limit
        let original_vsize = packager.total_vsize;
        packager.insert_item(RequestItem::no_votes().vsize(PACKAGE_MAX_VSIZE - original_vsize + 1));
        assert_eq!(packager.bags.len(), 2); // No change
        assert_eq!(packager.bags[0].items.len(), 3); // No change
        assert_eq!(packager.total_vsize, original_vsize); // No change to vsize

        // Check that we can trigger the OP_RETURN size limit roll-over
        (2..592).step_by(5).for_each(|id| {
            packager.insert_item(RequestItem::with_votes(&[1, 2]).wid(id));
        });
        assert_eq!(packager.bags.len(), 2); // we should be really close to the limit (no change)
        packager.insert_item(RequestItem::with_votes(&[1, 2]).wid(10_000));
        assert_eq!(packager.bags.len(), 3); // +1
    }

    /// End-to-end test of withdrawal ID handling in the packaging algorithm,
    /// verifying that IDs are properly distributed into bags that respect OP_RETURN size limits.
    #[test]
    fn test_withdrawal_id_packaging() {
        // Create a set of items with various withdrawal IDs
        let mut items = (0..600)
            .map(|id| RequestItem::no_votes().wid(id))
            .collect::<Vec<_>>();
        items.push(RequestItem::no_votes().sig_required().vsize(10)); // Regular deposit
        items.push(RequestItem::no_votes().wid(1000));
        items.push(RequestItem::no_votes().wid(2000));
        items.push(RequestItem::with_vote(1).wid(3000)); // Different vote pattern
        items.push(RequestItem::no_votes().wid(10000)); // Large ID

        let bags = compute_optimal_packages(items, 1, 5).collect::<Vec<_>>();

        // Verify multiple bags were created due to both vote and withdrawal ID constraints
        assert!(bags.len() > 1);

        // Verify each bag has the right vote pattern and withdrawal IDs
        for bag in &bags {
            // Check vote constraint
            let combined_votes = bag.iter().fold(0u128, |acc, item| acc | item.votes());

            // Collect withdrawal IDs
            let mut withdrawal_ids: Vec<u64> =
                bag.iter().filter_map(|item| item.withdrawal_id).collect();
            withdrawal_ids.sort_unstable();

            // Verify vote constraint is maintained
            assert!(
                combined_votes.count_ones() <= 1,
                "bag has more votes against than allowed: {}",
                combined_votes.count_ones()
            );

            // Verify withdrawal IDs can fit in OP_RETURN
            if !withdrawal_ids.is_empty() {
                let segmenter = BitmapSegmenter;
                let size = segmenter.estimate_size(&withdrawal_ids).unwrap();
                assert!(
                    size <= OP_RETURN_AVAILABLE_SIZE,
                    "withdrawal IDs exceed OP_RETURN size: {} > {}",
                    size,
                    OP_RETURN_AVAILABLE_SIZE
                );
            }
        }
    }
}
