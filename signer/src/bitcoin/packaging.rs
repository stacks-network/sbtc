//! Generic bin-packing functionality

use crate::MAX_MEMPOOL_PACKAGE_SIZE;
use crate::MAX_MEMPOOL_PACKAGE_TX_COUNT;

use super::utxo::MAX_BASE_TX_VSIZE;

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

/// Package a list of items into bags.
///
/// Each item is required to have certain "weights" that affect how it may
/// be included in a "bag". The weights are:
/// 1. The votes against. Each item is assumed to be "voted on" and each
///    bag cannot have items where the total number of votes against is
///    greater than the `max_votes_against`.
/// 2. Whether the item requires a signature. The total number of items in
///    a bag that require a signature must not exceed the
///    `max_needs_signature`.
/// 3. The items vsize, or virtual size. The aggregate vsize across all
///    bags must not exceed [`PACKAGE_MAX_VSIZE`].
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
    let mut packager =
        BestFitPackager::new(max_votes_against, max_needs_signature, PACKAGE_MAX_VSIZE);
    for (_, item) in item_vec {
        packager.insert_item(item);
    }
    packager.bags.into_iter().map(|(_, _, items)| items)
}

/// A weighted item that can be packaged using
/// [`compute_optimal_packages`].
///
/// The inclusion of a request in a bitcoin transaction depends on three
/// factors:
/// 1. How the signers have voted on the request,
/// 2. Whether we are dealing with a deposit or a withdrawal request,
/// 3. The virtual size of the request when included in a sweep
///    transaction.
///
/// This trait has methods that capture all of these factors.
pub trait Weighted {
    /// Whether the item needs a signature or not.
    ///
    /// If a request needs a signature, then including it requires a
    /// signing round and that takes time. Since we try to get all inputs
    /// signed well before the arrival of the next bitcoin block, we cap
    /// the number of items that need a signature.
    fn needs_signature(&self) -> bool;
    /// A bitmap of how the signers voted.
    ///
    /// Here, we assume that if a bit is 1 then the signer that corresponds
    /// to the bits position voted *against* the transaction.
    fn votes(&self) -> u128;
    /// The virtual size of the item in vbytes. This is supposed to be the
    /// total bitcoin weight of the request once signed on the bitcoin
    /// blockchain. For deposits this is the input UTXO including witness
    /// data, for withdrawals it's the entire output vsize.
    fn vsize(&self) -> u64;
}

#[derive(Debug)]
struct BestFitPackager<T> {
    /// Contains all the bags and their items. The first element of the
    /// tuple is a bitmap for how the signers would vote for the collection
    /// of items in the associated bag, the second element is the number of
    /// items that require signatures in the bag, and the third element is
    /// the bag itself.
    bags: Vec<(u128, u16, Vec<T>)>,
    /// Each bag has a fixed votes against threshold, this is that value.
    max_votes_against: u32,
    /// The maximum number of items that can require signatures in a bag,
    /// regardless of the aggregated votes and their vsize.
    max_needs_signature: u16,
    /// The maximum total virtual size of all bags.
    max_vsize: u64,
    /// The total virtual size of all items across all bags.
    total_vsize: u64,
}

impl<T: Weighted> BestFitPackager<T> {
    const fn new(max_votes_against: u32, max_needs_signature: u16, max_vsize: u64) -> Self {
        Self {
            bags: Vec::new(),
            max_votes_against,
            max_needs_signature,
            max_vsize,
            total_vsize: 0,
        }
    }

    /// Find the best bag to insert a new item given the item's weight
    /// and return the key for that bag. None is returned if no bag can
    /// accommodate an item with the given weight.
    fn find_best_key(&mut self, item: &T) -> Option<&mut (u128, u16, Vec<T>)> {
        let sig = item.needs_signature() as u16;
        let item_votes = item.votes();

        self.bags
            .iter_mut()
            .filter(|(aggregate_votes, num_signatures, _)| {
                (aggregate_votes | item_votes).count_ones() <= self.max_votes_against
                    && num_signatures.saturating_add(sig) <= self.max_needs_signature
            })
            .min_by_key(|(aggregate_votes, _, _)| (item_votes ^ aggregate_votes).count_ones())
    }

    /// Create a new bag for the given item.
    ///
    /// Note that this function creates a new bag even if the item can
    /// fit into some other bag with enough capacity
    fn create_new_bag(&mut self, item: T) {
        self.bags
            .push((item.votes(), item.needs_signature() as u16, vec![item]));
    }

    /// Try to insert an item into the best-fit bag, and create a new one
    /// if no bag exists that can fit the item and the item's weights are
    /// within the packager's limits.
    ///
    /// An item's weights exceed the packager's limits if any of the
    /// following conditions hold:
    /// 1. The votes against the item exceed the packager's
    ///    `max_votes_against`.
    /// 2. Including the item would bring the total vsize over the
    ///    packager's `max_vsize`.
    ///
    /// If the item's weights are not within the packager's limits, then it
    /// is not added to any bag and is dropped.
    fn insert_item(&mut self, item: T) {
        let item_votes = item.votes();
        let item_vsize = item.vsize();
        let above_limits = item_votes.count_ones() > self.max_votes_against
            || self.total_vsize.saturating_add(item_vsize) > self.max_vsize;

        if above_limits {
            return;
        }

        self.total_vsize += item_vsize;
        match self.find_best_key(&item) {
            Some((votes, num_signatures, items)) => {
                *votes |= item_votes;
                *num_signatures += item.needs_signature() as u16;
                items.push(item);
            }
            None => self.create_new_bag(item),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::array::BitArray;
    use bitvec::field::BitField;
    use test_case::test_case;

    #[derive(Debug, Copy, Clone)]
    struct RequestItem {
        votes: [bool; 5],
        needs_signature: bool,
        vsize: u64,
    }

    impl RequestItem {
        fn new(votes: [bool; 5], needs_signature: bool, vsize: u64) -> Self {
            Self { votes, needs_signature, vsize }
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

    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], false, 0); 6],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [6],
        expected_bag_vsizes: [0],
    } ; "no-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false, false, false, false, true], false, 0); 6],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [6],
        expected_bag_vsizes: [0],
    } ; "same-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![
            RequestItem::new([false, false, false, false, true], false, 0),
            RequestItem::new([false, false, false, false, true], false, 0),
            RequestItem::new([false, false, false, true, false], false, 0),
            RequestItem::new([false, false, false, true, false], false, 0),
            RequestItem::new([false, false, false, false, false], false, 0),
        ],
        max_needs_signature: 100,
        max_votes_against: 1,
        expected_bag_sizes: [3, 2],
        expected_bag_vsizes: [0, 0],
    } ; "two-different-votes-against-two-packages")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], true, 0); 25],
        max_needs_signature: 10,
        max_votes_against: 1,
        expected_bag_sizes: [10, 10, 5],
        expected_bag_vsizes: [0, 0, 0],
    } ; "splits-when-too-many-required-signatures")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], false, 4000); 25],
        max_needs_signature: 10,
        max_votes_against: 1,
        expected_bag_sizes: [23],
        expected_bag_vsizes: [92000],
    } ; "ignores-when-vsize-exceeds-max")]
    #[test_case(VotesTestCase {
        items: vec![
            RequestItem::new([false, false, false, true, true], false, 0),
            RequestItem::new([false, true, true, false, false], false, 0),
            RequestItem::new([true, true, false, false, false], false, 0),
            RequestItem::new([true, false, false, false, false], false, 0),
            RequestItem::new([false, true, false, false, false], false, 0),
            RequestItem::new([false, false, true, false, false], false, 0),
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
}
