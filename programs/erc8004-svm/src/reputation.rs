use crate::util::{decode_auth_struct, keccak_auth_struct, verify_ed25519};
use crate::{identity::Agent, E8004};
use anchor_lang::prelude::*;
use solana_program::sysvar;

pub const MAX_FILE_URI: usize = 256;

#[account]
pub struct ClientIndex {
    pub agent: Pubkey,
    pub client: Pubkey,
    pub last_index: u64,
    pub bump: u8,
}

#[account]
pub struct Feedback {
    pub agent: Pubkey,
    pub client: Pubkey,
    pub index: u64,
    pub score: u8,
    pub tag1: [u8; 32],
    pub tag2: [u8; 32],
    pub revoked: bool,
    pub file_uri: String,
    pub file_hash: [u8; 32],
    pub bump: u8,
}

#[derive(Accounts)]
#[instruction(expected_index: u64)]
pub struct GiveFeedbackCtx<'info> {
    pub agent: Account<'info, Agent>,

    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        init_if_needed,
        payer = client,
        space = 8 + 32 + 32 + 8 + 1,
        seeds=[b"idx", agent.key().as_ref(), client.key().as_ref()],
        bump
    )]
    pub idx: Account<'info, ClientIndex>,

    #[account(
        init,
        payer = client,
        space = 8 + 32 + 32 + 8 + 1 + 32 + 32 + 1 + 4 + MAX_FILE_URI + 32 + 1,
        seeds=[b"fb", agent.key().as_ref(), client.key().as_ref(), &expected_index.to_le_bytes()],
        bump
    )]
    pub feedback: Account<'info, Feedback>,

    #[account(address = sysvar::instructions::ID)]
    pub ix_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

pub fn give_feedback_ed25519(
    mut ctx: Context<GiveFeedbackCtx>,
    score: u8,
    tag1: [u8; 32],
    tag2: [u8; 32],
    file_uri: String,
    file_hash: [u8; 32],
    auth_struct_bytes: Vec<u8>,
    signature: Vec<u8>,
    expected_index: u64,
) -> Result<()> {
    require!(score <= 100, E8004::InvalidScore);
    require!(
        file_uri.as_bytes().len() <= MAX_FILE_URI,
        E8004::Unauthorized
    );
    require!(signature.len() == 64, E8004::BadSignature);

    let idx_bump = ctx.bumps.idx;
    let feedback_bump = ctx.bumps.feedback;
    let accounts = &mut ctx.accounts;

    let agent_key = accounts.agent.key();
    let agent_owner = accounts.agent.owner;
    let agent_id = accounts.agent.id;
    let client_key = accounts.client.key();

    require!(client_key != agent_owner, E8004::SelfFeedback);

    let auth_struct = decode_auth_struct(auth_struct_bytes)?;
    let digest = keccak_auth_struct(&auth_struct);
    require!(auth_struct.agent_id == agent_id, E8004::Unauthorized);
    require!(auth_struct.client == client_key, E8004::Unauthorized);

    let current_ts = Clock::get()?.unix_timestamp as u64;
    require!(current_ts < auth_struct.expiry, E8004::ExpiredAuth);
    require!(auth_struct.signer == agent_owner, E8004::Unauthorized);

    let signer_ok = verify_ed25519(
        &digest,
        signature.as_slice(),
        &auth_struct.signer,
        &accounts.ix_sysvar,
    );
    require!(signer_ok, E8004::BadSignature);

    let next_index = {
        let idx = &mut accounts.idx;
        if idx.last_index == 0 {
            idx.agent = agent_key;
            idx.client = client_key;
            idx.bump = idx_bump;
        }
        let next = idx.last_index.checked_add(1).unwrap();
        require!(expected_index == next, E8004::IndexLimit);
        require!(next <= auth_struct.index_limit, E8004::IndexLimit);
        idx.last_index = next;
        next
    };

    let feedback = &mut accounts.feedback;
    feedback.agent = agent_key;
    feedback.client = client_key;
    feedback.index = next_index;
    feedback.score = score;
    feedback.tag1 = tag1;
    feedback.tag2 = tag2;
    feedback.revoked = false;
    feedback.file_uri = file_uri;
    feedback.file_hash = file_hash;
    feedback.bump = feedback_bump;

    emit!(NewFeedback {
        agent: feedback.agent,
        client: feedback.client,
        score,
        tag1,
        tag2
    });

    Ok(())
}

#[derive(Accounts)]
pub struct RevokeFeedbackCtx<'info> {
    #[account(mut)]
    pub feedback: Account<'info, Feedback>,
    pub client: Signer<'info>,
}

pub fn revoke_feedback(mut ctx: Context<RevokeFeedbackCtx>, _index: u64) -> Result<()> {
    let accounts = &mut ctx.accounts;
    let client_key = accounts.client.key();
    let feedback = &mut accounts.feedback;

    require!(feedback.client == client_key, E8004::Unauthorized);
    require!(!feedback.revoked, E8004::Unauthorized);

    feedback.revoked = true;

    emit!(FeedbackRevoked {
        agent: feedback.agent,
        client: feedback.client,
        index: feedback.index
    });

    Ok(())
}

#[event]
pub struct NewFeedback {
    pub agent: Pubkey,
    pub client: Pubkey,
    pub score: u8,
    pub tag1: [u8; 32],
    pub tag2: [u8; 32],
}

#[event]
pub struct FeedbackRevoked {
    pub agent: Pubkey,
    pub client: Pubkey,
    pub index: u64,
}
