//! Quick Fair Queueing (Checconi, Valente, Rizzo 2013), one level.
//!
//! This is a compact re-statement of the algorithm behind Linux
//! `sch_qfq`, generic over the flow key so the same code runs at both
//! levels of the tree (classes at the top, streams inside a class):
//!
//! * every flow `k` has a weight `w_k`, a maximum packet length `L_k`, and
//!   virtual start/finish timestamps `S_k`/`F_k`;
//! * the system virtual time `V` advances by `len / W` on every service,
//!   where `W` is the sum of all registered weights;
//! * flows are bucketed into **groups** by `ceil(log2(L_k / w_k))`, so a
//!   group's slot size `σ_i = 2^i` bounds the timestamp error of its
//!   members — this is what makes selection O(1)-ish instead of a heap;
//! * a group is *eligible* when its (rounded) `S ≤ V` and *ready* when no
//!   eligible group with a larger slot has a smaller `F`; the served flow is
//!   the head of the lowest-index eligible-and-ready group.
//!
//! Differences from `sch_qfq` that do not change the schedule: group
//! states are recomputed from the group timestamps on every pick instead of
//! being cached in bitmaps (we have a handful of groups, not thousands of
//! packets per second), and timestamps are rebased instead of wrapping.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::Hash;

/// Fixed-point scale of `1 / w`. 2^20 keeps weight 1000 vs 1001
/// distinguishable while leaving ~2^30 frames of headroom before a rebase.
const ONE_FP: u64 = 1 << 20;
/// Slot size of group 0, as a shift. Anything smaller is folded into group 0.
const MIN_SLOT_SHIFT: u32 = 6;
/// Largest group index we allow, so `1 << (index + MIN_SLOT_SHIFT)` fits.
const MAX_INDEX: u32 = 56;
/// Rebase all timestamps once `V` passes this to keep additions overflow-free.
const REBASE_AT: u64 = 1 << 62;
/// Where `V` lands after a rebase; leaves room for stale `F` below it.
const REBASE_TO: u64 = 1 << 40;

#[derive(Debug, Clone)]
struct Flow {
    weight: u32,
    inv_w: u64,
    s: u64,
    f: u64,
    backlogged: bool,
    /// Length of the next packet this flow wants to send, given by the
    /// caller on activation and after each service.
    head_len: u32,
    group: u32,
}

#[derive(Debug)]
struct Group<K> {
    /// Flows bucketed by `round_down(S, shift)`; the first key is the group
    /// start time. Flows inside a slot are FIFO, as in `sch_qfq`.
    slots: BTreeMap<u64, VecDeque<K>>,
}

impl<K> Default for Group<K> {
    fn default() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }
}

impl<K: Eq> Group<K> {
    fn start(&self) -> Option<u64> {
        self.slots.keys().next().copied()
    }

    /// `F_i = S_i + 2σ_i`, the finish-time approximation `sch_qfq` uses.
    fn finish(&self, shift: u32) -> Option<u64> {
        self.start().map(|s| s + (2u64 << shift))
    }

    fn insert(&mut self, key: u64, k: K) {
        self.slots.entry(key).or_default().push_back(k);
    }

    fn remove(&mut self, key: u64, k: &K) {
        if let Some(q) = self.slots.get_mut(&key) {
            if let Some(pos) = q.iter().position(|x| x == k) {
                q.remove(pos);
            }
            if q.is_empty() {
                self.slots.remove(&key);
            }
        }
    }
}

/// One QFQ scheduler instance.
#[derive(Debug)]
pub struct Qfq<K> {
    flows: HashMap<K, Flow>,
    groups: BTreeMap<u32, Group<K>>,
    v: u64,
    wsum: u64,
}

impl<K: Copy + Eq + Hash> Default for Qfq<K> {
    fn default() -> Self {
        Self::new()
    }
}

fn round_down(ts: u64, shift: u32) -> u64 {
    (ts >> shift) << shift
}

fn ceil_log2(x: u64) -> u32 {
    if x <= 1 {
        0
    } else {
        64 - (x - 1).leading_zeros()
    }
}

/// `ceil(log2(lmax * inv_w))` relative to the minimum slot, clamped.
fn group_index(lmax: u32, inv_w: u64) -> u32 {
    let slot = u64::from(lmax).saturating_mul(inv_w);
    ceil_log2(slot)
        .saturating_sub(MIN_SLOT_SHIFT)
        .min(MAX_INDEX)
}

impl<K: Copy + Eq + Hash> Qfq<K> {
    /// Empty scheduler.
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            groups: BTreeMap::new(),
            v: 0,
            wsum: 0,
        }
    }

    /// Current system virtual time (exposed for tests and diagnostics).
    pub fn virtual_time(&self) -> u64 {
        self.v
    }

    /// True when at least one flow has a packet waiting.
    pub fn has_backlog(&self) -> bool {
        !self.groups.is_empty()
    }

    /// Register a flow. A flow registered while the scheduler is running
    /// re-enters at the current virtual time on its first activation
    /// (its stale `F` is zero, so `S = max(F, V) = V`).
    pub fn add_flow(&mut self, k: K, weight: u32, lmax: u32) {
        let weight = weight.max(1);
        let inv_w = ONE_FP / u64::from(weight);
        self.wsum += u64::from(weight);
        self.flows.insert(
            k,
            Flow {
                weight,
                inv_w,
                s: 0,
                f: 0,
                backlogged: false,
                head_len: 0,
                group: group_index(lmax.max(1), inv_w),
            },
        );
    }

    /// Forget a flow, deactivating it first if needed.
    pub fn remove_flow(&mut self, k: K) {
        self.deactivate(k);
        if let Some(flow) = self.flows.remove(&k) {
            self.wsum -= u64::from(flow.weight);
        }
    }

    /// Does the scheduler know this flow?
    pub fn contains(&self, k: K) -> bool {
        self.flows.contains_key(&k)
    }

    /// The flow has a packet of `head_len` bytes to send. No-op if it is
    /// already backlogged (use [`Qfq::served`] to advance it).
    pub fn activate(&mut self, k: K, head_len: u32) {
        let Some(flow) = self.flows.get_mut(&k) else {
            return;
        };
        if flow.backlogged {
            return;
        }
        let was_idle = self.groups.is_empty();
        // S = max(F, V): a flow that never left keeps its cadence, one that
        // has been idle re-enters at the current time.
        flow.s = flow.f.max(self.v);
        flow.f = flow.s + u64::from(head_len) * flow.inv_w;
        flow.backlogged = true;
        flow.head_len = head_len;
        let (group, key) = (flow.group, round_down(flow.s, flow.group + MIN_SLOT_SHIFT));
        if was_idle {
            // Work conservation: an idle system jumps to the newcomer so it
            // is eligible immediately instead of waiting for V to catch up.
            self.v = self.v.max(flow.s);
        }
        self.groups.entry(group).or_default().insert(key, k);
        self.maybe_rebase();
    }

    /// The flow has nothing to send (or lost its credit). Its `F` is kept
    /// so a quick return does not let it jump the queue.
    pub fn deactivate(&mut self, k: K) {
        let Some(flow) = self.flows.get_mut(&k) else {
            return;
        };
        if !flow.backlogged {
            return;
        }
        flow.backlogged = false;
        let key = round_down(flow.s, flow.group + MIN_SLOT_SHIFT);
        if let Some(g) = self.groups.get_mut(&flow.group) {
            g.remove(key, &k);
            if g.slots.is_empty() {
                self.groups.remove(&flow.group);
            }
        }
    }

    /// Is the flow currently backlogged?
    pub fn is_active(&self, k: K) -> bool {
        self.flows.get(&k).is_some_and(|f| f.backlogged)
    }

    /// Lowest-index group that is both eligible (`S ≤ V`) and ready (no
    /// eligible group with a larger slot has a smaller `F`). Advances `V`
    /// to the earliest group start when nothing is eligible, which is how
    /// QFQ stays work-conserving.
    fn pick_group(&mut self) -> Option<u32> {
        if self.groups.is_empty() {
            return None;
        }
        let any_eligible = self
            .groups
            .iter()
            .any(|(_, g)| g.start().is_some_and(|s| s <= self.v));
        if !any_eligible {
            let min_s = self.groups.values().filter_map(Group::start).min()?;
            self.v = self.v.max(min_s);
        }
        // Walk from the coarsest group down, tracking the smallest F seen
        // among eligible coarser groups; a finer group is ready iff its F
        // does not exceed that. The lowest ready index wins.
        let mut min_f_above = u64::MAX;
        let mut pick = None;
        for (&idx, g) in self.groups.iter().rev() {
            let shift = idx + MIN_SLOT_SHIFT;
            let (Some(s), Some(f)) = (g.start(), g.finish(shift)) else {
                continue;
            };
            if s > self.v {
                continue;
            }
            if f <= min_f_above {
                pick = Some(idx);
                min_f_above = f;
            }
        }
        pick
    }

    /// The flow that would be served next, without changing any state
    /// other than the work-conserving `V` jump.
    pub fn peek(&mut self) -> Option<K> {
        let idx = self.pick_group()?;
        let g = self.groups.get(&idx)?;
        g.slots.values().next().and_then(|q| q.front().copied())
    }

    /// Length of the packet [`Qfq::peek`] would serve.
    pub fn next_head_len(&mut self) -> Option<u32> {
        let k = self.peek()?;
        self.flows.get(&k).map(|f| f.head_len)
    }

    /// Account for `len` bytes served from flow `k`. `next_len` is the
    /// length of the flow's following packet, or `None` if it has nothing
    /// more to send and leaves the backlog.
    pub fn served(&mut self, k: K, len: u32, next_len: Option<u32>) {
        let Some(flow) = self.flows.get_mut(&k) else {
            return;
        };
        if !flow.backlogged {
            return;
        }
        let shift = flow.group + MIN_SLOT_SHIFT;
        let old_key = round_down(flow.s, shift);
        let group = flow.group;
        // Advance the flow: S ← F, F ← S + next_len / w.
        flow.s = flow.f;
        let new_key = match next_len {
            Some(n) => {
                flow.f = flow.s + u64::from(n) * flow.inv_w;
                flow.head_len = n;
                Some(round_down(flow.s, shift))
            }
            None => {
                flow.backlogged = false;
                flow.head_len = 0;
                None
            }
        };
        if let Some(g) = self.groups.get_mut(&group) {
            g.remove(old_key, &k);
            if let Some(key) = new_key {
                g.insert(key, k);
            }
            if g.slots.is_empty() {
                self.groups.remove(&group);
            }
        }
        if let Some(step) = (u64::from(len) * ONE_FP).checked_div(self.wsum) {
            self.v += step;
        }
        self.maybe_rebase();
    }

    /// Shift every timestamp down once `V` grows large so the fixed-point
    /// arithmetic never overflows on a long-lived connection. Rare (about
    /// once per 2^30 frames), so rebuilding the groups is fine.
    fn maybe_rebase(&mut self) {
        if self.v < REBASE_AT {
            return;
        }
        let delta = self.v - REBASE_TO;
        self.v = REBASE_TO;
        let mut groups: BTreeMap<u32, Group<K>> = BTreeMap::new();
        // Rebuild in a deterministic order so FIFO ties inside a slot are
        // preserved by S order rather than hash order.
        let mut active: Vec<(u64, K)> = Vec::new();
        for (k, flow) in self.flows.iter_mut() {
            flow.s = flow.s.saturating_sub(delta);
            flow.f = flow.f.saturating_sub(delta);
            if flow.backlogged {
                active.push((flow.s, *k));
            }
        }
        active.sort_by_key(|(s, _)| *s);
        for (_, k) in active {
            let flow = &self.flows[&k];
            let key = round_down(flow.s, flow.group + MIN_SLOT_SHIFT);
            groups.entry(flow.group).or_default().insert(key, k);
        }
        self.groups = groups;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Drive `n` services with every flow permanently backlogged with
    /// `len`-byte packets; return bytes served per flow.
    fn run(weights: &[u32], len: u32, n: usize) -> Vec<u64> {
        let mut q = Qfq::new();
        for (i, &w) in weights.iter().enumerate() {
            q.add_flow(i, w, len);
            q.activate(i, len);
        }
        let mut served = vec![0u64; weights.len()];
        let mut last_v = q.virtual_time();
        for _ in 0..n {
            let k = q.peek().expect("backlogged flows exist");
            served[k] += u64::from(len);
            q.served(k, len, Some(len));
            assert!(q.virtual_time() >= last_v, "V must be monotone");
            last_v = q.virtual_time();
        }
        served
    }

    #[test]
    fn shares_follow_weights() {
        let weights = [1000, 300, 300, 40];
        let served = run(&weights, 1000, 20_000);
        let total: u64 = served.iter().sum();
        let wsum: u64 = weights.iter().map(|&w| u64::from(w)).sum();
        for (i, &w) in weights.iter().enumerate() {
            let expected = total as f64 * f64::from(w) / wsum as f64;
            let err = (served[i] as f64 - expected).abs() / expected;
            assert!(
                err < 0.02,
                "flow {i}: served {} expected {expected}",
                served[i]
            );
        }
    }

    #[test]
    fn idle_flow_does_not_bank_credit() {
        // Flow 0 idles for a long time while flow 1 is served; when it
        // returns it must not monopolise the link to "catch up".
        let mut q = Qfq::new();
        q.add_flow(0, 1, 100);
        q.add_flow(1, 1, 100);
        q.activate(1, 100);
        for _ in 0..1000 {
            let k = q.peek().unwrap();
            assert_eq!(k, 1);
            q.served(k, 100, Some(100));
        }
        q.activate(0, 100);
        let mut count = [0i32, 0i32];
        for _ in 0..1000 {
            let k = q.peek().unwrap();
            count[k] += 1;
            q.served(k, 100, Some(100));
        }
        assert!((count[0] - count[1]).abs() <= 2, "{count:?}");
    }

    #[test]
    fn work_conserving_single_flow() {
        let mut q = Qfq::new();
        q.add_flow(0, 40, 100);
        q.add_flow(1, 1000, 100);
        q.activate(0, 100);
        for _ in 0..100 {
            assert_eq!(q.peek(), Some(0));
            q.served(0, 100, Some(100));
        }
    }

    #[test]
    fn activate_deactivate_idempotent() {
        let mut q = Qfq::new();
        q.add_flow(7, 1, 10);
        q.deactivate(7);
        q.activate(7, 10);
        q.activate(7, 20);
        assert!(q.is_active(7));
        assert_eq!(q.next_head_len(), Some(10), "second activate is a no-op");
        q.deactivate(7);
        q.deactivate(7);
        assert!(!q.is_active(7));
        assert_eq!(q.peek(), None);
        q.remove_flow(7);
        q.remove_flow(7);
        assert!(!q.contains(7));
    }

    #[test]
    fn rebase_preserves_order() {
        let mut q = Qfq::new();
        q.add_flow(0, 1, 100);
        q.add_flow(1, 1, 100);
        // Pretend the connection has been running for ages, then activate
        // so the timestamps are anchored near V as they would be in life.
        q.v = REBASE_AT - 1;
        q.activate(0, 100);
        q.activate(1, 100);
        // Serve enough to trigger a rebase and keep alternating afterwards.
        let mut seq = Vec::new();
        for _ in 0..8 {
            let k = q.peek().unwrap();
            seq.push(k);
            q.served(k, 100, Some(100));
        }
        assert!(q.virtual_time() < REBASE_AT);
        for w in seq.windows(2) {
            assert_ne!(w[0], w[1], "flows must keep alternating: {seq:?}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::default())]

        #[test]
        fn fairness_within_tolerance(
            weights in prop::collection::vec(1u32..=1000, 2..6),
            len in 5u32..=16384,
        ) {
            // QFQ's fairness error is a bounded number of packets, so the
            // lightest flow needs enough expected packets for that bound to
            // be a small fraction: run for ~100 of its packets.
            let wsum: u32 = weights.iter().sum();
            let min_w = *weights.iter().min().unwrap();
            let n = (100 * wsum / min_w).clamp(2000, 200_000) as usize;
            let served = run(&weights, len, n);
            let total: u64 = served.iter().sum();
            let wsum: u64 = weights.iter().map(|&w| u64::from(w)).sum();
            for (i, &w) in weights.iter().enumerate() {
                let expected = total as f64 * f64::from(w) / wsum as f64;
                // A flow with a very small share may be quantised to a few
                // packets; allow ±2 packets on top of a 5% tolerance.
                let slack = 0.05 * expected + 2.0 * f64::from(len);
                prop_assert!(
                    (served[i] as f64 - expected).abs() <= slack,
                    "flow {i} w={w}: served {} expected {expected}", served[i]
                );
            }
        }

        #[test]
        fn no_starvation(weights in prop::collection::vec(1u32..=1000, 2..6)) {
            // Run long enough that even the lightest flow expects several
            // packets, otherwise "starved" is just quantisation.
            let wsum: u32 = weights.iter().sum();
            let min_w = *weights.iter().min().unwrap();
            let n = (5 * wsum / min_w) as usize;
            let served = run(&weights, 1000, n);
            for (i, s) in served.iter().enumerate() {
                prop_assert!(*s > 0, "flow {i} starved: {served:?}");
            }
        }
    }
}
