// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod mem_store;
pub(crate) mod rocksdb_store;

#[cfg(test)]
mod store_tests;

use consensus_config::AuthorityIndex;

use crate::block::Slot;
use crate::{
    block::{BlockRef, Round, VerifiedBlock},
    commit::{CommitIndex, TrustedCommit},
    error::ConsensusResult,
};

/// A common interface for consensus storage.
pub(crate) trait Store: Send + Sync {
    /// Writes blocks and consensus commits to store.
    fn write(
        &self,
        blocks: Vec<VerifiedBlock>,
        commits: Vec<TrustedCommit>,
        last_committed_rounds: Vec<Round>,
    ) -> ConsensusResult<()>;

    /// Reads blocks for the given refs.
    fn read_blocks(&self, refs: &[BlockRef]) -> ConsensusResult<Vec<Option<VerifiedBlock>>>;

    /// Checks if blocks exist in the store.
    fn contains_blocks(&self, refs: &[BlockRef]) -> ConsensusResult<Vec<bool>>;

    /// Checks whether there is any block at the given slot
    fn contains_block_at_slot(&self, slot: Slot) -> ConsensusResult<bool>;

    /// Reads blocks for an authority, from start_round.
    fn scan_blocks_by_author(
        &self,
        authority: AuthorityIndex,
        start_round: Round,
    ) -> ConsensusResult<Vec<VerifiedBlock>>;

    // The method returns the last `num_of_rounds` rounds blocks by author in round ascending order.
    // When a `before_round` is defined then the blocks of round `<=before_round` are returned. If not
    // then the max value for round will be used as cut off.
    fn scan_last_blocks_by_author(
        &self,
        author: AuthorityIndex,
        num_of_rounds: u64,
        before_round: Option<Round>,
    ) -> ConsensusResult<Vec<VerifiedBlock>>;

    /// Reads the last commit.
    fn read_last_commit(&self) -> ConsensusResult<Option<TrustedCommit>>;

    /// Reads all commits from start_commit_index.
    fn scan_commits(&self, start_commit_index: CommitIndex) -> ConsensusResult<Vec<TrustedCommit>>;

    /// Reads the last committed rounds per authority.
    fn read_last_committed_rounds(&self) -> ConsensusResult<Vec<Round>>;
}
