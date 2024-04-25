use std::collections::BTreeMap;
use std::ops::Bound;

#[derive(Debug, Hash, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
struct BagId(u32);

const ZERO_BAG_ID: BagId = BagId(0);

/// A struct for solving the bin-packing problem using the Best-Fit
/// Decreasing approximation algorithm.
///
/// In bin packing, the problem is to pack a collection of items into a
/// minimum number of bins so that the sum of the sizes in each bin is
/// no greater than some capacity C.
///
/// The best-fit decreasing algorithm works as follows. You order the
/// items by their weight decreasing and iterate through them doing the
/// following: if there is no open bin in which the item at the front of
/// the list fits, then pack the item into an empty bin. Otherwise, pack
/// the item into an open bin of largest total weight in which it fits;
/// if there is more than one such bin choose the lowest indexed one.
#[derive(Debug)]
pub struct BestFitPackager<T> {
    /// The last ID of all bags contained by this struct.
    current_id: BagId,
    /// Contains all the bags and their items. The first element of the
    /// key tuple is how much capacity is left in the associated bag,
    /// while the second element is the ID of the bag itself. The values
    /// in this tree are the items themselves
    bags: BTreeMap<(u32, BagId), Vec<T>>,
    /// Each bag has a fixed capacity threshold, this is that value.
    capacity: u32,
}

pub trait Weighted {
    fn weight(&self) -> u32;
}

impl<T: Weighted> BestFitPackager<T> {
    pub const fn new(capacity: u32) -> Self {
        Self {
            current_id: ZERO_BAG_ID,
            bags: BTreeMap::new(),
            capacity,
        }
    }

    /// Find the best bag to insert a new item given the item's weight
    /// and return the key for said bag. None is returned if the no bag
    /// can accommodate an item with the given weight.
    fn find_best_key(&mut self, weight: u32) -> Option<(u32, BagId)> {
        let range = (Bound::Included((weight, ZERO_BAG_ID)), Bound::Unbounded);
        self.bags.range(range).next().map(|(&key, _)| key)
    }

    /// Create a new back for the given item.
    ///
    /// Note that this function creates a new bag even if the item can
    /// fit into some other back with enough capacity
    fn create_new_bag(&mut self, weight: u32, item: T) {
        self.current_id.0 += 1;
        let id = BagId(self.current_id.0);
        let capacity = self.capacity.saturating_sub(weight);
        self.bags.insert((capacity, id), vec![item]);
    }

    /// Insert an item into the best fit bag. And creates a new one if no
    /// bag exists that can fit the item.
    ///
    /// Note, this function assumes that the item's weight is less than
    /// this object's capacity.
    fn insert_item(&mut self, weight: u32, item: T) {
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

    /// Solve the bin packing problem by using the Best-Fit Decreasing
    /// algorithm. Assume each bag has the given capacity.
    pub fn compute_optimal_packages<I>(items: I, capacity: u32) -> impl Iterator<Item = Vec<T>>
    where
        I: IntoIterator<Item = T>,
    {
        // We need to sort the items by their weight decreasing.
        let mut item_vec: Vec<(u32, T)> = items
            .into_iter()
            .map(|item| (item.weight(), item))
            .collect();

        // This is a Best-Fit-Decreasing implementation so we need to sort
        // by weight decreasing.
        item_vec.sort_by_key(|(weight, _)| std::cmp::Reverse(*weight));

        // Now we just add each item into the a bag, and return the
        // collection of bags afterwards.
        let mut packager = Self::new(capacity);
        for (weight, req) in item_vec {
            packager.insert_item(weight, req);
        }
        packager.bags.into_iter().map(|(_, bag)| bag)
    }
}
