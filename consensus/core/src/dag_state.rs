// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet},
    ops::Bound::{Excluded, Included, Unbounded},
    panic,
    sync::Arc,
};

use consensus_config::AuthorityIndex;
use tracing::error;

use crate::block::GENESIS_ROUND;
use crate::stake_aggregator::{QuorumThreshold, StakeAggregator};
use crate::{
    block::{genesis_blocks, BlockAPI, BlockDigest, BlockRef, Round, Slot, VerifiedBlock},
    commit::{CommitAPI as _, CommitIndex, TrustedCommit},
    context::Context,
    storage::Store,
};

/// Rounds of recently committed blocks cached in memory, per authority.
#[allow(unused)]
const DEFAULT_CACHED_ROUNDS: Round = 100;

/// DagState provides the API to write and read accepted blocks from the DAG.
/// Only uncommited and last committed blocks are cached in memory.
/// The rest of blocks are stored on disk.
/// Refs to cached blocks and additional refs are cached as well, to speed up existence checks.
///
/// Note: DagState should be wrapped with Arc<parking_lot::RwLock<_>>, to allow
/// concurrent access from multiple components.
pub(crate) struct DagState {
    context: Arc<Context>,

    // The genesis blocks
    genesis: BTreeMap<BlockRef, VerifiedBlock>,

    // Contains recent blocks within CACHED_ROUNDS from the last committed round per authority.
    // Note: all uncommitted blocks are kept in memory.
    recent_blocks: BTreeMap<BlockRef, VerifiedBlock>,

    // Contains block refs of recent_blocks.
    // Each element in the Vec corresponds to the authority with the index.
    recent_refs: Vec<BTreeSet<BlockRef>>,

    // Highest round of blocks accepted.
    highest_accepted_round: Round,

    // Last consensus commit of the dag.
    last_commit: Option<TrustedCommit>,

    // Last committed rounds per authority.
    last_committed_rounds: Vec<Round>,

    // Buffered data to be flushed to storage.
    buffered_blocks: Vec<VerifiedBlock>,
    buffered_commits: Vec<TrustedCommit>,

    // Persistent storage for blocks, commits and other consensus data.
    store: Arc<dyn Store>,

    // The number of cached rounds
    cached_rounds: Round,
}

impl DagState {
    /// Initializes DagState from storage.
    pub(crate) fn new(
        context: Arc<Context>,
        store: Arc<dyn Store>,
        cached_rounds: Option<Round>,
    ) -> Self {
        let cached_rounds = cached_rounds.unwrap_or(DEFAULT_CACHED_ROUNDS);
        let num_authorities = context.committee.size();

        let genesis = genesis_blocks(context.clone())
            .into_iter()
            .map(|block| (block.reference(), block))
            .collect();

        let last_commit = store
            .read_last_commit()
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
        let last_committed_rounds = {
            let rounds = store
                .read_last_committed_rounds()
                .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
            if rounds.is_empty() {
                vec![0; num_authorities]
            } else {
                rounds
            }
        };

        let mut state = Self {
            context,
            genesis,
            recent_blocks: BTreeMap::new(),
            recent_refs: vec![BTreeSet::new(); num_authorities],
            highest_accepted_round: 0,
            last_commit,
            last_committed_rounds: last_committed_rounds.clone(),
            buffered_blocks: vec![],
            buffered_commits: vec![],
            store,
            cached_rounds,
        };

        for (i, round) in last_committed_rounds.into_iter().enumerate() {
            let authority_index = state.context.committee.to_authority_index(i).unwrap();
            let blocks = state
                .store
                .scan_blocks_by_author(authority_index, Self::evict_round(round, cached_rounds) + 1)
                .unwrap();
            for block in blocks {
                state.update_block_metadata(&block);
            }
        }

        state
    }

    /// Accepts a block into DagState and keeps it in memory.
    pub(crate) fn accept_block(&mut self, block: VerifiedBlock) {
        assert_ne!(
            block.round(),
            0,
            "Genesis block should not be accepted into DAG."
        );

        let block_ref = block.reference();
        if self.contains_block(&block_ref) {
            return;
        }

        // TODO: Move this check to core
        // Ensure we don't write multiple blocks per slot for our own index
        if block_ref.author == self.context.own_index {
            let existing_blocks = self.get_uncommitted_blocks_at_slot(block_ref.into());
            assert!(
                existing_blocks.is_empty(),
                "Block Rejected! Attempted to add block {block} to own slot where \
                block(s) {existing_blocks:#?} already exists."
            );
        }
        self.update_block_metadata(&block);
        self.buffered_blocks.push(block);
    }

    /// Updates internal metadata for a block.
    fn update_block_metadata(&mut self, block: &VerifiedBlock) {
        let block_ref = block.reference();
        self.recent_blocks.insert(block_ref, block.clone());
        self.recent_refs[block_ref.author].insert(block_ref);
        self.highest_accepted_round = max(self.highest_accepted_round, block.round());
    }

    /// Accepts a blocks into DagState and keeps it in memory.
    pub(crate) fn accept_blocks(&mut self, blocks: Vec<VerifiedBlock>) {
        for block in blocks {
            self.accept_block(block);
        }
    }

    /// Gets a block by checking cached recent blocks then storage.
    /// Returns None when the block is not found.
    pub(crate) fn get_block(&self, reference: &BlockRef) -> Option<VerifiedBlock> {
        self.get_blocks(&[*reference])
            .pop()
            .expect("Exactly one element should be returned")
    }

    /// Gets blocks by checking genesis, cached recent blocks in memory, then storage.
    /// An element is None when the corresponding block is not found.
    pub(crate) fn get_blocks(&self, block_refs: &[BlockRef]) -> Vec<Option<VerifiedBlock>> {
        let mut blocks = vec![None; block_refs.len()];
        let mut missing = Vec::new();

        for (index, block_ref) in block_refs.iter().enumerate() {
            if block_ref.round == GENESIS_ROUND {
                // Allow the caller to handle the invalid genesis ancestor error.
                if let Some(block) = self.genesis.get(block_ref) {
                    blocks[index] = Some(block.clone());
                }
                continue;
            }
            if let Some(block) = self.recent_blocks.get(block_ref) {
                blocks[index] = Some(block.clone());
                continue;
            }
            missing.push((index, block_ref));
        }

        if missing.is_empty() {
            return blocks;
        }

        let missing_refs = missing
            .iter()
            .map(|(_, block_ref)| **block_ref)
            .collect::<Vec<_>>();
        let store_results = self
            .store
            .read_blocks(&missing_refs)
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
        self.context
            .metrics
            .node_metrics
            .dag_state_store_read_count
            .with_label_values(&[&"get_blocks"])
            .inc();

        for ((index, _), result) in missing.into_iter().zip(store_results.into_iter()) {
            blocks[index] = result;
        }

        blocks
    }

    /// Gets all uncommitted blocks in a slot.
    /// Uncommitted blocks must exist in memory, so only in-memory blocks are checked.
    pub(crate) fn get_uncommitted_blocks_at_slot(&self, slot: Slot) -> Vec<VerifiedBlock> {
        // TODO: either panic below when the slot is at or below the last committed round,
        // or support reading from storage while limiting storage reads to edge cases.

        let mut blocks = vec![];
        for (_block_ref, block) in self.recent_blocks.range((
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MIN)),
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MAX)),
        )) {
            blocks.push(block.clone())
        }
        blocks
    }

    /// Gets all uncommitted blocks in a round.
    /// Uncommitted blocks must exist in memory, so only in-memory blocks are checked.
    pub(crate) fn get_uncommitted_blocks_at_round(&self, round: Round) -> Vec<VerifiedBlock> {
        if round <= self.last_commit_round() {
            panic!("Round {} have committed blocks!", round);
        }

        let mut blocks = vec![];
        for (_block_ref, block) in self.recent_blocks.range((
            Included(BlockRef::new(round, AuthorityIndex::ZERO, BlockDigest::MIN)),
            Excluded(BlockRef::new(
                round + 1,
                AuthorityIndex::ZERO,
                BlockDigest::MIN,
            )),
        )) {
            blocks.push(block.clone())
        }
        blocks
    }

    /// Gets all ancestors in the history of a block at a certain round.
    pub(crate) fn ancestors_at_round(
        &self,
        later_block: &VerifiedBlock,
        earlier_round: Round,
    ) -> Vec<VerifiedBlock> {
        // Iterate through ancestors of later_block in round descending order.
        let mut linked: BTreeSet<BlockRef> = later_block.ancestors().iter().cloned().collect();
        while !linked.is_empty() {
            let round = linked.last().unwrap().round;
            // Stop after finishing traversal for ancestors above earlier_round.
            if round <= earlier_round {
                break;
            }
            let block_ref = linked.pop_last().unwrap();
            let Some(block) = self.get_block(&block_ref) else {
                panic!("Block {:?} should exist in DAG!", block_ref);
            };
            linked.extend(block.ancestors().iter().cloned());
        }
        linked
            .range((
                Included(BlockRef::new(
                    earlier_round,
                    AuthorityIndex::ZERO,
                    BlockDigest::MIN,
                )),
                Unbounded,
            ))
            .map(|r| {
                self.get_block(r)
                    .unwrap_or_else(|| panic!("Block {:?} should exist in DAG!", r))
                    .clone()
            })
            .collect()
    }

    pub(crate) fn contains_block(&self, block_ref: &BlockRef) -> bool {
        let blocks = self.contains_blocks(vec![*block_ref]);
        blocks.first().cloned().unwrap()
    }

    /// Retrieves the last block proposed for the specified `authority`. If no block is found in cache
    /// then the genesis block is returned as no other block has been received from that authority.
    pub(crate) fn get_last_block_for_authority(&self, authority: AuthorityIndex) -> VerifiedBlock {
        if let Some(last) = self.recent_refs[authority].last() {
            return self
                .recent_blocks
                .get(last)
                .expect("Block should be found in recent blocks")
                .clone();
        }

        // if none exists, then fallback to genesis
        let (_, genesis_block) = self
            .genesis
            .iter()
            .find(|(block_ref, _)| block_ref.author == authority)
            .expect("Genesis should be found for authority {authority_index}");
        genesis_block.clone()
    }

    /// Returns the last block proposed per authority with round <= `before_round`. If `before_round`
    /// is not provided then block of the highest available round per authority will be returned.
    /// The method is guaranteed to return results only when the `before_round` is not earlier of the
    /// available cached data for each authority, otherwise the method will panic - it's the caller's
    /// responsibility to ensure that is not requesting filtering for earlier rounds .
    /// In case of equivocation for an authority's last slot only one block will be returned (the last in order).
    pub(crate) fn get_last_cached_block_per_authority(
        &self,
        before_round: Option<Round>,
    ) -> Vec<VerifiedBlock> {
        let before_round = before_round.unwrap_or(u32::MAX - 1);

        // init with the genesis blocks as fallback
        let mut blocks = self.genesis.values().cloned().collect::<Vec<_>>();

        if before_round == GENESIS_ROUND {
            return blocks;
        }

        for (authority_index, block_refs) in self.recent_refs.iter().enumerate() {
            let authority_index = self
                .context
                .committee
                .to_authority_index(authority_index)
                .unwrap();

            let last_evicted_round = self.authority_evict_round(authority_index);
            if before_round <= last_evicted_round {
                panic!("Attempted to request for blocks of rounds <= {before_round}, that is bellow the last evicted round {last_evicted_round} for authority {authority_index}", );
            }

            if let Some(block_ref) = block_refs
                .range((
                    Included(BlockRef::new(
                        last_evicted_round + 1,
                        authority_index,
                        BlockDigest::MIN,
                    )),
                    Excluded(BlockRef::new(
                        before_round + 1,
                        authority_index,
                        BlockDigest::MIN,
                    )),
                ))
                .next_back()
            {
                let block = self
                    .recent_blocks
                    .get(block_ref)
                    .expect("Block should exist in recent blocks");

                blocks[authority_index] = block.clone();
            }
        }

        blocks.into_iter().collect()
    }

    /// Checks whether a block exists in the slot. The method checks only against the cached data.
    /// If the user asks for a slot that is not within the cached data then a panic is thrown.
    pub(crate) fn contains_cached_block_at_slot(&self, slot: Slot) -> bool {
        // Always return true for genesis slots.
        if slot.round == GENESIS_ROUND {
            return true;
        }

        if slot.round <= self.authority_evict_round(slot.authority) {
            panic!("Attempted to check for slot {slot} that is <= the last evicted round {} for the authority", self.authority_evict_round(slot.authority));
        }

        let mut result = self.recent_refs[slot.authority].range((
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MIN)),
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MAX)),
        ));
        result.next().is_some()
    }

    /// Checks whether the required blocks are in cache, if exist, or otherwise will check in store. The method is not caching
    /// back the results, so its expensive if keep asking for cache missing blocks.
    pub(crate) fn contains_blocks(&self, block_refs: Vec<BlockRef>) -> Vec<bool> {
        let mut exist = vec![false; block_refs.len()];
        let mut missing = Vec::new();

        for (index, block_ref) in block_refs.into_iter().enumerate() {
            let recent_refs = &self.recent_refs[block_ref.author];
            if recent_refs.contains(&block_ref) || self.genesis.contains_key(&block_ref) {
                exist[index] = true;
            } else if recent_refs.is_empty() || recent_refs.last().unwrap().round < block_ref.round
            {
                // Optimization: recent_refs contain the most recent blocks known to this authority.
                // If a block ref is not found there and has a higher round, it definitely is
                // missing from this authority and there is no need to check disk.
                exist[index] = false;
            } else {
                missing.push((index, block_ref));
            }
        }

        if missing.is_empty() {
            return exist;
        }

        let missing_refs = missing
            .iter()
            .map(|(_, block_ref)| *block_ref)
            .collect::<Vec<_>>();
        let store_results = self
            .store
            .contains_blocks(&missing_refs)
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
        self.context
            .metrics
            .node_metrics
            .dag_state_store_read_count
            .with_label_values(&[&"contains_blocks"])
            .inc();

        for ((index, _), result) in missing.into_iter().zip(store_results.into_iter()) {
            exist[index] = result;
        }

        exist
    }

    pub(crate) fn highest_accepted_round(&self) -> Round {
        self.highest_accepted_round
    }

    // Buffers a new commit in memory and updates last committed rounds.
    // REQUIRED: must not skip over any commit index.
    pub(crate) fn add_commit(&mut self, commit: TrustedCommit) {
        if let Some(last_commit) = &self.last_commit {
            if commit.index() <= last_commit.index() {
                error!(
                    "New commit index {} <= last commit index {}!",
                    commit.index(),
                    last_commit.index()
                );
                return;
            }
            assert_eq!(commit.index(), last_commit.index() + 1);
        } else {
            assert_eq!(commit.index(), 1);
        }
        self.last_commit = Some(commit.clone());
        for block_ref in commit.blocks().iter() {
            self.last_committed_rounds[block_ref.author] = max(
                self.last_committed_rounds[block_ref.author],
                block_ref.round,
            );
        }
        self.buffered_commits.push(commit);
    }

    /// Index of the last commit.
    pub(crate) fn last_commit_index(&self) -> CommitIndex {
        match &self.last_commit {
            Some(commit) => commit.index(),
            None => 0,
        }
    }

    /// Leader slot of the last commit.
    pub(crate) fn last_commit_leader(&self) -> Slot {
        match &self.last_commit {
            Some(commit) => commit.leader().into(),
            None => self
                .genesis
                .iter()
                .next()
                .map(|(genesis_ref, _)| *genesis_ref)
                .expect("Genesis blocks should always be available.")
                .into(),
        }
    }

    /// Last committed round per authority.
    pub(crate) fn last_committed_rounds(&self) -> Vec<Round> {
        self.last_committed_rounds.clone()
    }

    /// After each flush, DagState becomes persisted in storage and it expected to recover
    /// all internal states from storage after restarts.
    pub(crate) fn flush(&mut self) {
        // Flush buffered data to storage.
        let blocks = std::mem::take(&mut self.buffered_blocks);
        let commits = std::mem::take(&mut self.buffered_commits);
        if blocks.is_empty() && commits.is_empty() {
            return;
        }
        self.store
            .write(blocks, commits, self.last_committed_rounds.clone())
            .unwrap_or_else(|e| panic!("Failed to write to storage: {:?}", e));
        self.context
            .metrics
            .node_metrics
            .dag_state_store_write_count
            .inc();

        // Clean up old cached data. After flushing, all cached blocks are guaranteed to be persisted.
        for (authority_refs, last_committed_round) in self
            .recent_refs
            .iter_mut()
            .zip(self.last_committed_rounds.iter())
        {
            while let Some(block_ref) = authority_refs.first() {
                if block_ref.round <= Self::evict_round(*last_committed_round, self.cached_rounds) {
                    self.recent_blocks.remove(block_ref);
                    authority_refs.pop_first();
                } else {
                    break;
                }
            }
        }
    }

    /// Detects and returns the blocks of the round that forms the last quorum. The method will return
    /// the quorum even if that's genesis.
    pub(crate) fn last_quorum(&self) -> Vec<VerifiedBlock> {
        // the quorum should exist either on the highest accepted round or the one before. If we fail to detect
        // a quorum then it means that our DAG has advanced with missing causal history.
        for round in
            (self.highest_accepted_round.saturating_sub(1)..=self.highest_accepted_round).rev()
        {
            if round == GENESIS_ROUND {
                return self.genesis_blocks();
            }
            let mut quorum = StakeAggregator::<QuorumThreshold>::new();

            // Since that the minimum wave length is 3 we expect to find a quorum in the uncommitted rounds.
            let blocks = self.get_uncommitted_blocks_at_round(round);
            for block in &blocks {
                if quorum.add(block.author(), &self.context.committee) {
                    return blocks;
                }
            }
        }

        panic!("Fatal error, no quorum has been detected in our DAG on the last two rounds.");
    }

    pub(crate) fn genesis_blocks(&self) -> Vec<VerifiedBlock> {
        self.genesis.values().cloned().collect()
    }

    /// Highest round where a block is committed, which is last commit's leader round.
    fn last_commit_round(&self) -> Round {
        match &self.last_commit {
            Some(commit) => commit.leader().round,
            None => 0,
        }
    }

    /// The last round that got evicted after a cache clean up operation. After this round we are
    /// guaranteed to have all the produced blocks from that authority. For any round that is
    /// <= `last_evicted_round` we don't have such guarantees as out of order blocks might exist.
    fn authority_evict_round(&self, authority_index: AuthorityIndex) -> Round {
        let commit_round = self.last_committed_rounds[authority_index];
        Self::evict_round(commit_round, self.cached_rounds)
    }

    /// Calculates the last eviction round based on the provided `commit_round`. Any blocks with
    /// round <= the evict round have been cleaned up.
    fn evict_round(commit_round: Round, cached_rounds: Round) -> Round {
        commit_round.saturating_sub(cached_rounds).saturating_sub(1)
    }
}

#[cfg(test)]
mod test {
    use parking_lot::RwLock;
    use std::vec;

    use super::*;
    use crate::test_dag::build_dag;
    use crate::{
        block::{BlockDigest, BlockRef, BlockTimestampMs, TestBlock, VerifiedBlock},
        storage::mem_store::MemStore,
    };

    #[test]
    fn test_get_blocks() {
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone(), None);
        let own_index = AuthorityIndex::new_for_test(0);

        // Populate test blocks for round 1 ~ 10, authorities 0 ~ 2.
        let num_rounds: u32 = 10;
        let non_existent_round: u32 = 100;
        let num_authorities: u32 = 3;
        let num_blocks_per_slot: usize = 3;
        let mut blocks = BTreeMap::new();
        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                // Create 3 blocks per slot, with different timestamps and digests.
                let base_ts = round as BlockTimestampMs * 1000;
                for timestamp in base_ts..base_ts + num_blocks_per_slot as u64 {
                    let block = VerifiedBlock::new_for_test(
                        TestBlock::new(round, author)
                            .set_timestamp_ms(timestamp)
                            .build(),
                    );
                    dag_state.accept_block(block.clone());
                    blocks.insert(block.reference(), block);

                    // Only write one block per slot for own index
                    if AuthorityIndex::new_for_test(author) == own_index {
                        break;
                    }
                }
            }
        }

        // Check uncommitted blocks that exist.
        for (r, block) in &blocks {
            assert_eq!(&dag_state.get_block(r).unwrap(), block);
        }

        // Check uncommitted blocks that do not exist.
        let last_ref = blocks.keys().last().unwrap();
        assert!(dag_state
            .get_block(&BlockRef::new(
                last_ref.round,
                last_ref.author,
                BlockDigest::MIN
            ))
            .is_none());

        // Check slots with uncommitted blocks.
        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let slot = Slot::new(
                    round,
                    context
                        .committee
                        .to_authority_index(author as usize)
                        .unwrap(),
                );
                let blocks = dag_state.get_uncommitted_blocks_at_slot(slot);

                // We only write one block per slot for own index
                if AuthorityIndex::new_for_test(author) == own_index {
                    assert_eq!(blocks.len(), 1);
                } else {
                    assert_eq!(blocks.len(), num_blocks_per_slot);
                }

                for b in blocks {
                    assert_eq!(b.round(), round);
                    assert_eq!(
                        b.author(),
                        context
                            .committee
                            .to_authority_index(author as usize)
                            .unwrap()
                    );
                }
            }
        }

        // Check slots without uncommitted blocks.
        let slot = Slot::new(non_existent_round, AuthorityIndex::ZERO);
        assert!(dag_state.get_uncommitted_blocks_at_slot(slot).is_empty());

        // Check rounds with uncommitted blocks.
        for round in 1..=num_rounds {
            let blocks = dag_state.get_uncommitted_blocks_at_round(round);
            // Expect 3 blocks per authority except for own authority which should
            // have 1 block.
            assert_eq!(
                blocks.len(),
                (num_authorities - 1) as usize * num_blocks_per_slot + 1
            );
            for b in blocks {
                assert_eq!(b.round(), round);
            }
        }

        // Check rounds without uncommitted blocks.
        assert!(dag_state
            .get_uncommitted_blocks_at_round(non_existent_round)
            .is_empty());
    }

    #[test]
    fn test_ancestors_at_uncommitted_round() {
        // Initialize DagState.
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone(), None);

        // Populate DagState.

        // Round 10 refs will not have their blocks in DagState.
        let round_10_refs: Vec<_> = (0..4)
            .map(|a| {
                VerifiedBlock::new_for_test(TestBlock::new(10, a).set_timestamp_ms(1000).build())
                    .reference()
            })
            .collect();

        // Round 11 blocks.
        let round_11 = vec![
            // This will connect to round 12.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 0)
                    .set_timestamp_ms(1100)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // Slot(11, 1) has 3 blocks.
            // This will connect to round 12.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 1)
                    .set_timestamp_ms(1110)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will connect to round 13.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 1)
                    .set_timestamp_ms(1111)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will not connect to any block.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 1)
                    .set_timestamp_ms(1112)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will not connect to any block.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 2)
                    .set_timestamp_ms(1120)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will connect to round 12.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 3)
                    .set_timestamp_ms(1130)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
        ];

        // Round 12 blocks.
        let ancestors_for_round_12 = vec![
            round_11[0].reference(),
            round_11[1].reference(),
            round_11[5].reference(),
        ];
        let round_12 = vec![
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 0)
                    .set_timestamp_ms(1200)
                    .set_ancestors(ancestors_for_round_12.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 2)
                    .set_timestamp_ms(1220)
                    .set_ancestors(ancestors_for_round_12.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 3)
                    .set_timestamp_ms(1230)
                    .set_ancestors(ancestors_for_round_12.clone())
                    .build(),
            ),
        ];

        // Round 13 blocks.
        let ancestors_for_round_13 = vec![
            round_12[0].reference(),
            round_12[1].reference(),
            round_12[2].reference(),
            round_11[2].reference(),
        ];
        let round_13 = vec![
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 1)
                    .set_timestamp_ms(1300)
                    .set_ancestors(ancestors_for_round_13.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 2)
                    .set_timestamp_ms(1320)
                    .set_ancestors(ancestors_for_round_13.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 3)
                    .set_timestamp_ms(1330)
                    .set_ancestors(ancestors_for_round_13.clone())
                    .build(),
            ),
        ];

        // Round 14 anchor block.
        let ancestors_for_round_14 = round_13.iter().map(|b| b.reference()).collect();
        let anchor = VerifiedBlock::new_for_test(
            TestBlock::new(14, 1)
                .set_timestamp_ms(1410)
                .set_ancestors(ancestors_for_round_14)
                .build(),
        );

        // Add all blocks (at and above round 11) to DagState.
        for b in round_11
            .iter()
            .chain(round_12.iter())
            .chain(round_13.iter())
            .chain([anchor.clone()].iter())
        {
            dag_state.accept_block(b.clone());
        }

        // Check ancestors connected to anchor.
        let ancestors = dag_state.ancestors_at_round(&anchor, 11);
        let mut ancestors_refs: Vec<BlockRef> = ancestors.iter().map(|b| b.reference()).collect();
        ancestors_refs.sort();
        let mut expected_refs = vec![
            round_11[0].reference(),
            round_11[1].reference(),
            round_11[2].reference(),
            round_11[5].reference(),
        ];
        expected_refs.sort(); // we need to sort as blocks with same author and round of round 11 (position 1 & 2) might not be in right lexicographical order.
        assert_eq!(
            ancestors_refs, expected_refs,
            "Expected round 11 ancestors: {:?}. Got: {:?}",
            expected_refs, ancestors_refs
        );
    }

    #[test]
    fn test_contains_blocks_in_cache_or_store() {
        /// Only keep elements up to 2 rounds before the last committed round
        const CACHED_ROUNDS: Round = 2;

        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone(), Some(CACHED_ROUNDS));

        // Create test blocks for round 1 ~ 10
        let num_rounds: u32 = 10;
        let num_authorities: u32 = 4;
        let mut blocks = Vec::new();

        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                blocks.push(block.clone());
                dag_state.accept_blocks(vec![block]);
            }
        }

        // Now when trying to query whether we have all the blocks, we should successfully retrieve a positive answer
        // where the blocks of first 4 round should be found in DagState and the rest in store.
        let mut block_refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state.contains_blocks(block_refs.clone());

        // Ensure everything is found
        let mut expected = vec![true; (num_rounds * num_authorities) as usize];
        assert_eq!(result, expected);

        // Attempt to check the same via the contains slot method
        for block_ref in block_refs.clone() {
            let slot = block_ref.into();
            let found = dag_state.contains_cached_block_at_slot(slot);
            assert!(found, "A block should be found at slot {}", slot);
        }

        // Now try to ask also for one block ref that is neither in cache nor in store
        block_refs.insert(
            3,
            BlockRef::new(11, AuthorityIndex::new_for_test(3), BlockDigest::default()),
        );
        let result = dag_state.contains_blocks(block_refs.clone());

        // Then all should be found apart from the last one
        expected.insert(3, false);
        assert_eq!(result, expected.clone());

        // Attempt to check the same for via the contains slot method
        for block_ref in block_refs.clone() {
            let slot = block_ref.into();
            let found = dag_state.contains_cached_block_at_slot(slot);

            assert_eq!(expected.remove(0), found);
        }
    }

    #[test]
    fn test_get_blocks_in_cache_or_store() {
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone(), None);

        // Create test blocks for round 1 ~ 10
        let num_rounds: u32 = 10;
        let num_authorities: u32 = 4;
        let mut blocks = Vec::new();

        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                blocks.push(block);
            }
        }

        // Now write in store the blocks from first 4 rounds and the rest to the dag state
        blocks.clone().into_iter().for_each(|block| {
            if block.round() <= 4 {
                store.write(vec![block], vec![], vec![]).unwrap();
            } else {
                dag_state.accept_blocks(vec![block]);
            }
        });

        // Now when trying to query whether we have all the blocks, we should successfully retrieve a positive answer
        // where the blocks of first 4 round should be found in DagState and the rest in store.
        let mut block_refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state.get_blocks(&block_refs);

        let mut expected = blocks
            .into_iter()
            .map(Some)
            .collect::<Vec<Option<VerifiedBlock>>>();

        // Ensure everything is found
        assert_eq!(result, expected.clone());

        // Now try to ask also for one block ref that is neither in cache nor in store
        block_refs.insert(
            3,
            BlockRef::new(11, AuthorityIndex::new_for_test(3), BlockDigest::default()),
        );
        let result = dag_state.get_blocks(&block_refs);

        // Then all should be found apart from the last one
        expected.insert(3, None);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_flush_and_recovery() {
        let num_authorities: u32 = 4;
        let (context, _) = Context::new_for_test(num_authorities as usize);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone(), None);

        // Create test blocks and commits for round 1 ~ 10
        let num_rounds: u32 = 10;
        let mut blocks = Vec::new();
        let mut commits = Vec::new();
        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                blocks.push(block);
            }
            commits.push(TrustedCommit::new_for_test(
                round as CommitIndex,
                blocks.last().unwrap().reference(),
                vec![],
            ));
        }

        // Add the blocks from first 5 rounds and first 5 commits to the dag state
        let i = blocks.iter().position(|b| b.round() == 5).unwrap();
        let temp_blocks = blocks.split_off(i);
        dag_state.accept_blocks(blocks.clone());
        let temp_commits = commits.split_off(5);
        for commit in commits.clone() {
            dag_state.add_commit(commit);
        }

        // Flush the dag state
        dag_state.flush();

        // Add the rest of the blocks and commits to the dag state
        dag_state.accept_blocks(temp_blocks.clone());
        for commit in temp_commits.clone() {
            dag_state.add_commit(commit);
        }

        // All blocks should be found in DagState.
        let all_blocks = blocks
            .clone()
            .into_iter()
            .chain(temp_blocks.clone())
            .collect::<Vec<_>>();
        let block_refs = all_blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state
            .get_blocks(&block_refs)
            .into_iter()
            .map(|b| b.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(result, all_blocks);

        // Last commit index should be 10.
        assert_eq!(dag_state.last_commit_index(), 10);

        // Destroy the dag state.
        drop(dag_state);

        // Recover the state from the store
        let dag_state = DagState::new(context.clone(), store.clone(), None);

        // Blocks of first 5 rounds should be found in DagState.
        let block_refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state
            .get_blocks(&block_refs)
            .into_iter()
            .map(|b| b.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(result, blocks);

        // Blocks above round 5 should not be in DagState, because they are not flushed.
        let block_refs = temp_blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let retrieved_blocks = dag_state
            .get_blocks(&block_refs)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert!(retrieved_blocks.is_empty());

        // Last commit index should be 5.
        assert_eq!(dag_state.last_commit_index(), 5);
    }

    #[test]
    fn test_get_cached_last_block_per_authority() {
        // GIVEN
        const CACHED_ROUNDS: Round = 2;
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone(), Some(CACHED_ROUNDS));

        // Create no blocks for authority 0
        // Create one block (round 1) for authority 1
        // Create two blocks (rounds 1,2) for authority 2
        // Create three blocks (rounds 1,2,3) for authority 3
        let mut all_blocks = Vec::new();
        for author in 1..=3 {
            for round in 1..=author {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                all_blocks.push(block.clone());
                dag_state.accept_block(block);
            }
        }

        dag_state.add_commit(TrustedCommit::new_for_test(
            1 as CommitIndex,
            all_blocks.last().unwrap().reference(),
            all_blocks
                .into_iter()
                .map(|block| block.reference())
                .collect::<Vec<_>>(),
        ));

        // WHEN search for the latest blocks
        let before_round = 2;
        let last_blocks = dag_state.get_last_cached_block_per_authority(Some(before_round));

        // THEN
        assert_eq!(last_blocks[0].round(), 0);
        assert_eq!(last_blocks[1].round(), 1);
        assert_eq!(last_blocks[2].round(), 2);
        assert_eq!(last_blocks[3].round(), 2);

        // WHEN we flush the DagState - after adding a commit with all the blocks, we expect this to trigger
        // a clean up in the internal cache. That will keep the all the blocks with rounds >= authority_commit_round - CACHED_ROUND.
        dag_state.flush();

        // AND we request before round 1
        let before_round = 1;
        let last_blocks = dag_state.get_last_cached_block_per_authority(Some(before_round));

        // THEN
        assert_eq!(last_blocks[0].round(), 0);
        assert_eq!(last_blocks[1].round(), 1);
        assert_eq!(last_blocks[2].round(), 1);
        assert_eq!(last_blocks[3].round(), 1);
    }

    #[test]
    #[should_panic(
        expected = "Attempted to request for blocks of rounds <= 1, that is bellow the last evicted round 1 for authority D"
    )]
    fn test_get_cached_last_block_per_authority_requesting_out_of_round_range() {
        // GIVEN
        const CACHED_ROUNDS: Round = 1;
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone(), Some(CACHED_ROUNDS));

        // Create no blocks for authority 0
        // Create one block (round 1) for authority 1
        // Create two blocks (rounds 1,2) for authority 2
        // Create three blocks (rounds 1,2,3) for authority 3
        let mut all_blocks = Vec::new();
        for author in 1..=3 {
            for round in 1..=author {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                all_blocks.push(block.clone());
                dag_state.accept_block(block);
            }
        }

        dag_state.add_commit(TrustedCommit::new_for_test(
            1 as CommitIndex,
            all_blocks.last().unwrap().reference(),
            all_blocks
                .into_iter()
                .map(|block| block.reference())
                .collect::<Vec<_>>(),
        ));

        // Flush the store so we keep in memory only the last 1 round from the last commit for each
        // authority.
        dag_state.flush();

        // THEN the method should panic, as some authorities have already evicted rounds <= round 2
        let before_round = 1;
        dag_state.get_last_cached_block_per_authority(Some(before_round));
    }

    #[test]
    fn test_last_quorum() {
        // GIVEN
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(
            context.clone(),
            store.clone(),
            None,
        )));

        // WHEN no blocks exist then genesis should be returned
        {
            let genesis = genesis_blocks(context.clone());

            assert_eq!(dag_state.read().last_quorum(), genesis);
        }

        // WHEN a fully connected DAG up to round 4 is created, then round 4 blocks should be returned as quorum
        {
            let round_4_blocks = build_dag(context, dag_state.clone(), None, 4);

            let last_quorum = dag_state.read().last_quorum();

            assert_eq!(
                last_quorum
                    .into_iter()
                    .map(|block| block.reference())
                    .collect::<Vec<_>>(),
                round_4_blocks
            );
        }

        // WHEN adding one more block at round 5, still round 4 should be returned as quorum
        {
            let block = VerifiedBlock::new_for_test(TestBlock::new(5, 0).build());
            dag_state.write().accept_block(block);

            let round_4_blocks = dag_state.read().get_uncommitted_blocks_at_round(4);

            let last_quorum = dag_state.read().last_quorum();

            assert_eq!(last_quorum, round_4_blocks);
        }
    }

    #[test]
    fn test_last_block_for_authority() {
        // GIVEN
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(
            context.clone(),
            store.clone(),
            None,
        )));

        // WHEN no blocks exist then genesis should be returned
        {
            let genesis = genesis_blocks(context.clone());
            let my_genesis = genesis
                .into_iter()
                .find(|block| block.author() == context.own_index)
                .unwrap();

            assert_eq!(
                dag_state
                    .read()
                    .get_last_block_for_authority(context.own_index),
                my_genesis
            );
        }

        // WHEN adding some blocks for authorities, only the last ones should be returned
        {
            // add blocks up to round 4
            build_dag(context.clone(), dag_state.clone(), None, 4);

            // add block 5 for authority 0
            let block = VerifiedBlock::new_for_test(TestBlock::new(5, 0).build());
            dag_state.write().accept_block(block);

            let block = dag_state
                .read()
                .get_last_block_for_authority(AuthorityIndex::new_for_test(0));
            assert_eq!(block.round(), 5);

            for (authority_index, _) in context.committee.authorities() {
                let block = dag_state
                    .read()
                    .get_last_block_for_authority(authority_index);

                if authority_index.value() == 0 {
                    assert_eq!(block.round(), 5);
                } else {
                    assert_eq!(block.round(), 4);
                }
            }
        }
    }
}
