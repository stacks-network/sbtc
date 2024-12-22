//! Generic bin-packing functionality

/// The maximum size of a transaction package that can exist in the mempool
/// at any given time in vbytes.
///
/// A transaction package is one or more transactions that are linked in by
/// inputs and outputs, and in this context it refers to a group of
/// transactions in the mempool. This value comes from the limits set in
/// bitcoin core, less 6000 vbytes since to make its use here much more
/// simple.
///
/// The actual limit is 101,000 vbytes, see:
/// <https://bitcoincore.reviews/21800>
/// <https://github.com/bitcoin/bitcoin/blob/v25.0/src/policy/policy.h#L60-L61>
const MEMPOOL_ANCESTORS_MAX_VSIZE: u64 = 95_000;

/// Package a list of items into bags.
///
/// The items are assumed to be "voted on" and each bag cannot have items
/// where the total number of distinct votes against is less than or equal
/// to the `max_votes_against`. Moreover, each item has a weight, and the
/// total weight of each bag must be less than or equal to the max_weight.
pub fn compute_optimal_packages<I, T>(
    items: I,
    max_votes_against: u32,
    max_signatures: u16,
) -> impl Iterator<Item = Vec<T>>
where
    I: IntoIterator<Item = T>,
    T: Weighted,
{
    // This is an implementation of the Best-Fit-Decreasing algorithm, so
    // we need to sort by weight decreasing.
    let mut item_vec: Vec<(u32, T)> = items
        .into_iter()
        .map(|item| (item.votes().count_ones(), item))
        .collect();

    item_vec.sort_by_key(|(vote_count, _)| std::cmp::Reverse(*vote_count));

    // Now we just add each item into a bag, and return the
    // collection of bags afterward.
    let mut packager = OptimalPackager::new(
        max_votes_against,
        max_signatures,
        MEMPOOL_ANCESTORS_MAX_VSIZE,
    );
    for (_, item) in item_vec {
        packager.insert_item(item);
    }
    packager.bags.into_iter().map(|(_, _, items)| items)
}

/// A weighted item that can be packaged using [`compute_optimal_packages`].
///
/// The inclusion of a request in a bitcoin transaction depends on three
/// factors:
/// 1. How the signers have voted on the request,
/// 2. Whether we are dealing with a deposit or a withdrawal request,
/// 3. The virtual size of the request when included in a sweep
///    transaction.
pub trait Weighted {
    /// Whether the item needs a signature or not.
    ///
    /// If a request needs a signature, then including it requires a
    /// signing round and that takes time. We try to get all inputs signed
    /// well before the arrival of the next bitcoin block.
    fn needs_signature(&self) -> bool;
    /// A bitmap of how the signers voted. Here, we assume that a 1 (or
    /// true) implies that the signer voted *against* the transaction.
    fn votes(&self) -> u128;
    /// The virtual size of the item in vbytes. This is supposed to be the
    /// total weight of the requests on chain. For deposits, this is the
    /// input UTXO including witness data, for outputs it's the entire
    /// output vsize.
    fn vsize(&self) -> u64;
}

#[derive(Debug)]
struct OptimalPackager<T> {
    /// Contains all the bags and their items. The first element of the
    /// tuple is a bitmap for how the signers would vote for the collection
    /// of items in the associated bag, while the second element is the
    /// number of items that require signatures in the bag itself.
    bags: Vec<(u128, u16, Vec<T>)>,
    /// Each bag has a fixed capacity threshold, this is that value.
    max_votes_against: u32,
    /// The maximum number of items that can require signatures in a bag,
    /// regardless of the aggregated votes and their vsize.
    max_signatures: u16,
    /// The maximum total virtual size of all bags.
    max_vsize: u64,
    /// The total virtual size of all items across all bags.
    total_vsize: u64,
}

impl<T: Weighted> OptimalPackager<T> {
    const fn new(max_votes_against: u32, max_signatures: u16, max_vsize: u64) -> Self {
        Self {
            bags: Vec::new(),
            max_votes_against,
            max_signatures,
            max_vsize,
            total_vsize: 0,
        }
    }

    /// Find the best bag to insert a new item given the item's weight
    /// and return the key for that bag. None is returned if no bag can
    /// accommodate an item with the given weight.
    fn find_best_key(&mut self, item: &T) -> Option<&mut (u128, u16, Vec<T>)> {
        self.bags
            .iter_mut()
            .find(|(aggregate_votes, num_signatures, _)| {
                let sig = item.needs_signature() as u16;
                (aggregate_votes | item.votes()).count_ones() <= self.max_votes_against
                    && num_signatures.saturating_add(sig) <= self.max_signatures
            })
    }

    /// Create a new bag for the given item.
    ///
    /// Note that this function creates a new bag even if the item can
    /// fit into some other bag with enough capacity
    fn create_new_bag(&mut self, item: T) {
        self.bags
            .push((item.votes(), item.needs_signature() as u16, vec![item]));
    }

    /// Insert an item into the best fit bag. Creates a new one if no
    /// bag exists that can fit the item.
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
        max_signatures: u16,
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
        max_signatures: 100,
        max_votes_against: 1,
        expected_bag_sizes: [6],
        expected_bag_vsizes: [0],
    } ; "no-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false, false, false, false, true], false, 0); 6],
        max_signatures: 100,
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
        max_signatures: 100,
        max_votes_against: 1,
        expected_bag_sizes: [3, 2],
        expected_bag_vsizes: [0, 0],
    } ; "two-different-votes-against-two-packages")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], true, 0); 25],
        max_signatures: 10,
        max_votes_against: 1,
        expected_bag_sizes: [10, 10, 5],
        expected_bag_vsizes: [0, 0, 0],
    } ; "splits-when-too-many-required-signatures")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], false, 4000); 25],
        max_signatures: 10,
        max_votes_against: 1,
        expected_bag_sizes: [23],
        expected_bag_vsizes: [92000],
    } ; "ignores-when-vsize-exceeds-max")]
    fn returns_optimal_placements<const N: usize>(case: VotesTestCase<N>) {
        let ans = compute_optimal_packages(case.items, case.max_votes_against, case.max_signatures);
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
            more_asserts::assert_le!(package_vsize, MEMPOOL_ANCESTORS_MAX_VSIZE);
        }
    }
}
