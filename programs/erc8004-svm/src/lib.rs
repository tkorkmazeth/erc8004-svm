#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod identity;
pub mod reputation;
pub mod util;
pub mod validation;

use identity::{AgentRegisterCtx, AgentSetMetaCtx, InitPlatformCtx};
use reputation::{GiveFeedbackCtx, RevokeFeedbackCtx};
use validation::{ValidationRequestCtx, ValidationResponseCtx};

// === Re-export client account ctx builders for Anchor 0.30 ===
// These are emitted by Anchor build tooling normally. Since we compile
// with plain `cargo build`, we expose them manually from our modules.

pub(crate) use identity::{
    __client_accounts_agent_register_ctx, __client_accounts_agent_set_meta_ctx,
    __client_accounts_init_platform_ctx,
};

pub(crate) use reputation::{
    __client_accounts_give_feedback_ctx, __client_accounts_revoke_feedback_ctx,
};

pub(crate) use validation::{
    __client_accounts_validation_request_ctx, __client_accounts_validation_response_ctx,
};

// Anchor 0.30 expects build tooling to emit these modules for the `client` feature.
// We compile the program directly with `cargo build`, so we provide empty stubs to
// satisfy the references emitted by the `#[program]` macro.
#[allow(non_snake_case)]
pub mod __client_accounts_identity {}
#[allow(non_snake_case)]
pub mod __client_accounts_reputation {}
#[allow(non_snake_case)]
pub mod __client_accounts_validation {}

declare_id!("F3471nQ1BYRVUL2RUGRfC5JToakHkweBmLAMoMFBjo9d");

#[program]
pub mod erc8004_svm {
    use super::*;

    pub fn init_platform(ctx: Context<InitPlatformCtx>) -> Result<()> {
        identity::init_platform(ctx)
    }

    pub fn agent_register(ctx: Context<AgentRegisterCtx>, token_uri: String) -> Result<()> {
        identity::agent_register(ctx, token_uri)
    }

    pub fn agent_set_metadata(
        ctx: Context<AgentSetMetaCtx>,
        key: String,
        value: Vec<u8>,
        key_hash: [u8; 32],
    ) -> Result<()> {
        identity::agent_set_metadata(ctx, key, value, key_hash)
    }

    pub fn give_feedback_ed25519(
        ctx: Context<GiveFeedbackCtx>,
        score: u8,
        tag1: [u8; 32],
        tag2: [u8; 32],
        file_uri: String,
        file_hash: [u8; 32],
        auth_struct_bytes: Vec<u8>,
        signature: Vec<u8>,
        expected_index: u64,
    ) -> Result<()> {
        reputation::give_feedback_ed25519(
            ctx,
            score,
            tag1,
            tag2,
            file_uri,
            file_hash,
            auth_struct_bytes,
            signature,
            expected_index,
        )
    }

    pub fn revoke_feedback(ctx: Context<RevokeFeedbackCtx>, index: u64) -> Result<()> {
        reputation::revoke_feedback(ctx, index)
    }

    pub fn validation_request(
        ctx: Context<ValidationRequestCtx>,
        validator: Pubkey,
        request_uri: String,
        request_hash: [u8; 32],
    ) -> Result<()> {
        validation::validation_request(ctx, validator, request_uri, request_hash)
    }

    pub fn validation_response(
        ctx: Context<ValidationResponseCtx>,
        response: u8,
        response_uri: String,
        response_hash: [u8; 32],
        tag: [u8; 32],
    ) -> Result<()> {
        validation::validation_response(ctx, response, response_uri, response_hash, tag)
    }
}

#[error_code]
pub enum E8004 {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Agent not found")]
    AgentNotFound,
    #[msg("Invalid score")]
    InvalidScore,
    #[msg("Invalid response")]
    InvalidResponse,
    #[msg("Expired authorization")]
    ExpiredAuth,
    #[msg("Index limit exceeded")]
    IndexLimit,
    #[msg("Self feedback not allowed")]
    SelfFeedback,
    #[msg("Request already exists")]
    RequestExists,
    #[msg("Request not found")]
    RequestNotFound,
    #[msg("Signature invalid")]
    BadSignature,
}
