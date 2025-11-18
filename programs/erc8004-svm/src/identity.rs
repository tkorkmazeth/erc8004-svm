use crate::E8004;
use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

pub const FEATURE_NFT: bool = false;
pub const MAX_TOKEN_URI: usize = 256;
pub const MAX_META_VAL: usize = 1024;

#[account]
pub struct Platform {
    pub authority: Pubkey,
    pub agent_counter: u64,
    pub bump: u8,
}

#[account]
pub struct Agent {
    pub id: u64,
    pub owner: Pubkey,
    pub token_mint: Option<Pubkey>,
    pub token_uri: String,
    pub bump: u8,
}

#[account]
pub struct MetaKV {
    pub agent: Pubkey,
    pub key_hash: [u8; 32],
    pub value: Vec<u8>,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct InitPlatformCtx<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 1,
        seeds = [b"platform"],
        bump
    )]
    pub platform: Account<'info, Platform>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn init_platform(mut ctx: Context<InitPlatformCtx>) -> Result<()> {
    let platform_bump = ctx.bumps.platform;
    let accounts = &mut ctx.accounts;
    let p = &mut accounts.platform;

    p.authority = accounts.authority.key();
    p.agent_counter = 1;
    p.bump = platform_bump;

    Ok(())
}

#[derive(Accounts)]
pub struct AgentRegisterCtx<'info> {
    #[account(
        mut,
        seeds = [b"platform"],
        bump = platform.bump,
        has_one = authority
    )]
    pub platform: Account<'info, Platform>,

    pub authority: Signer<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer = owner,
        space = 8 + 8 + 32 + 1 + 32 + 4 + MAX_TOKEN_URI + 1,
        seeds = [b"agent", platform.key().as_ref(), &platform.agent_counter.to_le_bytes()],
        bump
    )]
    pub agent: Account<'info, Agent>,

    pub system_program: Program<'info, System>,

    // optional mint if FEATURE_NFT == true (omit in v1)
    pub mint: Option<Account<'info, Mint>>,
}

pub fn agent_register(mut ctx: Context<AgentRegisterCtx>, token_uri: String) -> Result<()> {
    let agent_bump = ctx.bumps.agent;
    require!(
        token_uri.as_bytes().len() <= MAX_TOKEN_URI,
        E8004::Unauthorized
    );

    let accounts = &mut ctx.accounts;
    let p = &mut accounts.platform;
    let next = p.agent_counter;

    let a = &mut accounts.agent;
    a.id = next;
    a.owner = accounts.owner.key();
    a.token_uri = token_uri;
    a.token_mint = None;
    a.bump = agent_bump;

    p.agent_counter = p.agent_counter.checked_add(1).unwrap();

    emit!(AgentRegistered {
        agent: a.key(),
        id: a.id,
        owner: a.owner
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(key_hash: [u8;32])]
pub struct AgentSetMetaCtx<'info> {
    #[account(mut, has_one = owner)]
    pub agent: Account<'info, Agent>,

    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + 32 + 32 + 4 + MAX_META_VAL + 1,
        seeds=[b"meta", agent.key().as_ref(), &key_hash],
        bump
    )]
    pub meta: Account<'info, MetaKV>,

    pub system_program: Program<'info, System>,
}

pub fn agent_set_metadata(
    mut ctx: Context<AgentSetMetaCtx>,
    key: String,
    value: Vec<u8>,
    key_hash: [u8; 32],
) -> Result<()> {
    let meta_bump = ctx.bumps.meta;
    require!(!key.is_empty(), E8004::Unauthorized);
    require!(value.len() <= MAX_META_VAL, E8004::Unauthorized);

    let computed = crate::util::keccak_bytes(key.as_bytes());
    require!(computed == key_hash, E8004::Unauthorized);

    let accounts = &mut ctx.accounts;
    let m = &mut accounts.meta;
    m.agent = accounts.agent.key();
    m.key_hash = key_hash;
    m.value = value;
    m.bump = meta_bump;

    emit!(MetadataSet {
        agent: m.agent,
        key_hash: m.key_hash
    });

    Ok(())
}

#[event]
pub struct AgentRegistered {
    pub agent: Pubkey,
    pub id: u64,
    pub owner: Pubkey,
}

#[event]
pub struct MetadataSet {
    pub agent: Pubkey,
    pub key_hash: [u8; 32],
}
