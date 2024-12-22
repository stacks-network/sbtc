//! Generic bin-packing functionality

use std::collections::BTreeMap;

/// The maximum size of a transaction package that can exist in the mempool
/// at any given time in vbytes.
///
/// A transaction package is one or more transactions that are linked in by
/// inputs and outputs, and in this context it refers to a group of
/// transactions in the mempool. This value comes from the limits set in
/// bitcoin core, less 6000 vbytes since to make it's use here much more
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
pub fn compute_optimal_packages2<I, T>(
    items: I,
    max_votes_against: u32,
    max_signatures: u16,
) -> impl Iterator<Item = Vec<T>>
where
    I: IntoIterator<Item = T>,
    T: Weighted2,
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
pub trait Weighted2 {
    /// A bitmap of how the signers voted. Here, we assume that a 1 (or
    /// true) implies that the signer voted *against* the transaction.
    fn votes(&self) -> u128;
    /// Whether the item needs a signature or not.
    ///
    /// If a request needs a signature, then including it requires a
    /// signing round and that takes time. We try to get all inputs signed
    /// well before the arrival of the next bitcoin block.
    fn needs_signature(&self) -> bool;
    /// The virtual size of the item in vbytes. This is supposed to be the
    /// total weight of the requests on chain. For deposits, this is the
    /// input UTXO including witness data, for outputs its the entire
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

impl<T: Weighted2> OptimalPackager<T> {
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

/// Package a list of items into bags where the total capacity of each bag
/// is less than the given capacity.
///
/// Note that items with weight that is greater than the capacity are
/// filtered out.
pub fn compute_optimal_packages<I, T>(items: I, capacity: u32) -> impl Iterator<Item = Vec<T>>
where
    I: IntoIterator<Item = T>,
    T: Weighted,
{
    // This is an implementation of the Best-Fit-Decreasing algorithm, so
    // we need to sort by weight decreasing.
    let mut item_vec: Vec<(u32, T)> = items
        .into_iter()
        .map(|item| (item.weight(), item))
        .collect();

    item_vec.sort_by_key(|(weight, _)| std::cmp::Reverse(*weight));

    // Now we just add each item into a bag, and return the
    // collection of bags afterward.
    let mut packager = BestFitPackager::new(capacity);
    for (weight, req) in item_vec {
        packager.insert_item(weight, req);
    }
    packager.bags.into_values()
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
struct BagId(u32);

const ZERO_BAG_ID: BagId = BagId(0);

/// A struct for solving the bin-packing problem using the Best-Fit
/// Decreasing approximation algorithm.
///
/// In bin packing, the problem is to pack a collection of items into the
/// minimum number of bins so that the sum of the sizes in each bin is
/// no greater than some capacity C.
///
/// The best-fit decreasing algorithm works as follows. You order the
/// items by their weight decreasing and iterate through them doing the
/// following: if there is no open bin in which the item fits, then put
/// the item into an empty bin; otherwise, pack the item into an open bin
/// of largest total weight in which it fits and if there is more than one
/// such bin choose the lowest indexed one.
#[derive(Debug)]
struct BestFitPackager<T> {
    /// The next ID of all bags contained by this struct.
    next_id: BagId,
    /// Contains all the bags and their items. The first element of the
    /// key tuple is how much capacity is left in the associated bag,
    /// while the second element is the ID of the bag itself. The values
    /// in this tree are the items themselves.
    bags: BTreeMap<(u32, BagId), Vec<T>>,
    /// Each bag has a fixed capacity threshold, this is that value.
    capacity: u32,
}

/// A weighted item that can be packaged using [`compute_optimal_packages`].
pub trait Weighted {
    /// The weight of the item in the context of packaging.
    fn weight(&self) -> u32;
}

impl<T> BestFitPackager<T> {
    const fn new(capacity: u32) -> Self {
        Self {
            next_id: ZERO_BAG_ID,
            bags: BTreeMap::new(),
            capacity,
        }
    }

    /// Find the best bag to insert a new item given the item's weight
    /// and return the key for that bag. None is returned if no bag can
    /// accommodate an item with the given weight.
    fn find_best_key(&mut self, weight: u32) -> Option<(u32, BagId)> {
        self.bags
            .range((weight, ZERO_BAG_ID)..)
            .next()
            .map(|(&key, _)| key)
    }

    /// Create a new bag for the given item.
    ///
    /// Note that this function creates a new bag even if the item can
    /// fit into some other bag with enough capacity
    fn create_new_bag(&mut self, weight: u32, item: T) {
        let id = BagId(self.next_id.0);
        self.next_id.0 += 1;

        let capacity = self.capacity.saturating_sub(weight);
        self.bags.insert((capacity, id), vec![item]);
    }

    /// Insert an item into the best fit bag. Creates a new one if no
    /// bag exists that can fit the item.
    fn insert_item(&mut self, weight: u32, item: T) {
        if weight > self.capacity {
            return;
        }

        let entry = self
            .find_best_key(weight)
            .and_then(|key| self.bags.remove_entry(&key));

        match entry {
            Some(((capacity, id), mut bag)) => {
                let key = (capacity - weight, id);
                bag.push(item);
                self.bags.insert(key, bag);
            }
            None => self.create_new_bag(weight, item),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::array::BitArray;
    use bitvec::field::BitField;
    use test_case::test_case;

    #[derive(Debug)]
    struct Item(u32);

    impl Weighted for Item {
        fn weight(&self) -> u32 {
            self.0
        }
    }

    #[test_case(&[48, 30, 19, 36, 36, 27, 42, 42, 36, 24, 30], 100; "or-tools example")]
    #[test_case(&[5, 7, 5, 2, 4, 2, 5, 1, 6], 10; "uci example")]
    #[test_case(&[6, 1, 0, 3, 0, 4, 4, 0, 0, 2], 10; "made-up example")]
    #[test_case(&[11, 4, 1, 0, 3, 0, 4, 4, 0, 10, 2], 10; "heavy items example")]
    fn returned_bags_within_capacity_limit(weights: &[u32], capacity: u32) {
        let items = weights.iter().copied().map(Item);

        for bag in compute_optimal_packages(items, capacity) {
            let total_weight: u32 = bag.iter().map(Weighted::weight).sum();
            more_asserts::assert_le!(total_weight, capacity);
            assert!(!bag.is_empty());
        }
    }

    /// We want to use as few bags as possible for packaging the given
    /// input "items". If OPL represents the optimal number of bags, then
    /// this algorithm packages into N bags N <= (11 / 9) * OPL + 1
    #[test_case(&[5, 7, 5, 2, 4, 2, 5, 1, 6], 10, 4; "uci example")]
    #[test_case(&[6, 1, 0, 3, 0, 4, 4, 0, 0, 2], 10, 2; "made-up example")]
    fn returned_nearly_optimal_solutions(weights: &[u32], capacity: u32, optimal: usize) {
        let items = weights.iter().copied().map(Item);
        let bags: Vec<Vec<Item>> = compute_optimal_packages(items, capacity).collect();

        more_asserts::assert_le!(bags.len(), optimal * 11 / 9 + 1);
    }

    #[test_case(&[0, 1, 0, 0, 0, 1, 0, 0, 0, 0], 4, 1; "made-up example 1")]
    #[test_case(&[6, 1, 0, 3, 0, 4, 4, 0, 0, 2], 10, 2; "made-up example 2")]
    fn happy_path(weights: &[u32], capacity: u32, expected: usize) {
        let items = weights.iter().copied().map(Item);
        let bags: Vec<Vec<Item>> = compute_optimal_packages(items, capacity).collect();

        assert_eq!(bags.len(), expected);
    }

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

    impl Weighted2 for RequestItem {
        fn votes(&self) -> u128 {
            let mut votes = BitArray::<[u8; 16]>::ZERO;
            for (index, value) in self.votes.iter().copied().enumerate() {
                votes.set(index, value);
            }
            votes.load()
        }
        fn needs_signature(&self) -> bool {
            self.needs_signature
        }
        fn vsize(&self) -> u64 {
            self.vsize
        }
    }

    struct VotesTestCase<const N: usize> {
        items: Vec<RequestItem>,
        max_signatures: u16,
        max_votes_against: u32,
        expected_package_sizes: [usize; N],
        expected_package_vsizes: [u64; N],
    }

    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], false, 0); 6],
        max_signatures: 100,
        max_votes_against: 1,
        expected_package_sizes: [6],
        expected_package_vsizes: [0],
    } ; "no-votes-against-one-package")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false, false, false, false, true], false, 0); 6],
        max_signatures: 100,
        max_votes_against: 1,
        expected_package_sizes: [6],
        expected_package_vsizes: [0],
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
        expected_package_sizes: [3, 2],
        expected_package_vsizes: [0, 0],
    } ; "two-different-votes-against-two-packages")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], true, 0); 25],
        max_signatures: 10,
        max_votes_against: 1,
        expected_package_sizes: [10, 10, 5],
        expected_package_vsizes: [0, 0, 0],
    } ; "splits-when-too-many-required-signatures")]
    #[test_case(VotesTestCase {
        items: vec![RequestItem::new([false; 5], false, 4000); 25],
        max_signatures: 10,
        max_votes_against: 1,
        expected_package_sizes: [23],
        expected_package_vsizes: [92000],
    } ; "ignores-when-vsize-exceeds-max")]
    fn returns_optimal_placements<const N: usize>(case: VotesTestCase<N>) {
        let ans =
            compute_optimal_packages2(case.items, case.max_votes_against, case.max_signatures);
        let collection = ans.collect::<Vec<_>>();
        let iter = collection
            .iter()
            .zip(case.expected_package_sizes)
            .zip(case.expected_package_vsizes);

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
