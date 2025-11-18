use crate::util::keccak_bytes;
use crate::{identity::Agent, E8004};
use anchor_lang::prelude::*;

pub const MAX_REQUEST_URI: usize = 256;
pub const MAX_RESPONSE_URI: usize = 256;

#[account]
pub struct ValidationRequest {
    pub agent: Pubkey,
    pub validator: Pubkey,
    pub request_uri: String,
    pub request_hash: [u8; 32],
    pub timestamp: i64,
    pub bump: u8,
}

#[account]
pub struct ValidationResponse {
    pub request: Pubkey,
    pub validator: Pubkey,
    pub agent: Pubkey,
    pub response: u8,
    pub tag: [u8; 32],
    pub last_update: i64,
    pub response_uri: String,
    pub response_hash: [u8; 32],
    pub bump: u8,
}

#[derive(Accounts)]
#[instruction(request_hash: [u8;32])]
pub struct ValidationRequestCtx<'info> {
    #[account(mut, constraint = agent.owner == owner.key() @ E8004::Unauthorized)]
    pub agent: Account<'info, Agent>,

    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 32 + 4 + MAX_REQUEST_URI + 32 + 8 + 1,
        seeds=[b"vreq", agent.key().as_ref(), &request_hash],
        bump
    )]
    pub request: Account<'info, ValidationRequest>,

    pub system_program: Program<'info, System>,
}

pub fn validation_request(
    mut ctx: Context<ValidationRequestCtx>,
    validator: Pubkey,
    request_uri: String,
    request_hash: [u8; 32],
) -> Result<()> {
    let request_bump = ctx.bumps.request;
    let accounts = &mut ctx.accounts;
    let owner_key = accounts.owner.key();

    require!(validator != owner_key, E8004::Unauthorized);
    require!(
        request_uri.as_bytes().len() <= MAX_REQUEST_URI,
        E8004::Unauthorized
    );

    let computed = keccak_bytes(
        &[
            validator.as_ref(),
            accounts.agent.id.to_le_bytes().as_ref(),
            request_uri.as_bytes(),
        ]
        .concat(),
    );
    require!(computed == request_hash, E8004::Unauthorized);

    let request = &mut accounts.request;
    request.agent = accounts.agent.key();
    request.validator = validator;
    request.request_uri = request_uri;
    request.request_hash = computed;
    request.timestamp = Clock::get()?.unix_timestamp;
    request.bump = request_bump;

    emit!(ValidationRequestEv {
        validator,
        agent: request.agent,
        request: request.key(),
        request_hash: computed
    });

    Ok(())
}

#[derive(Accounts)]
pub struct ValidationResponseCtx<'info> {
    #[account(mut)]
    pub request: Account<'info, ValidationRequest>,

    #[account(mut)]
    pub validator: Signer<'info>,

    #[account(
        init_if_needed,
        payer = validator,
        space = 8 + 32 + 32 + 1 + 32 + 8 + 4 + MAX_RESPONSE_URI + 32 + 1,
        seeds=[b"vres", request.key().as_ref()],
        bump
    )]
    pub response_acc: Account<'info, ValidationResponse>,

    pub system_program: Program<'info, System>,
}

pub fn validation_response(
    mut ctx: Context<ValidationResponseCtx>,
    response: u8,
    response_uri: String,
    response_hash: [u8; 32],
    tag: [u8; 32],
) -> Result<()> {
    let response_bump = ctx.bumps.response_acc;
    let accounts = &mut ctx.accounts;
    let validator_key = accounts.validator.key();

    require!(response <= 100, E8004::InvalidResponse);
    require!(
        accounts.request.validator == validator_key,
        E8004::Unauthorized
    );
    require!(
        response_uri.as_bytes().len() <= MAX_RESPONSE_URI,
        E8004::Unauthorized
    );

    let request_key = accounts.request.key();
    let request_validator = accounts.request.validator;
    let request_agent = accounts.request.agent;
    let last_update = Clock::get()?.unix_timestamp;

    let response_acc = &mut accounts.response_acc;
    response_acc.request = request_key;
    response_acc.validator = request_validator;
    response_acc.agent = request_agent;
    response_acc.response = response;
    response_acc.tag = tag;
    response_acc.last_update = last_update;
    response_acc.response_uri = response_uri;
    response_acc.response_hash = response_hash;
    response_acc.bump = response_bump;

    emit!(ValidationResponseEv {
        validator: response_acc.validator,
        agent: response_acc.agent,
        request: response_acc.request,
        response,
        tag
    });

    Ok(())
}

#[event]
pub struct ValidationRequestEv {
    pub validator: Pubkey,
    pub agent: Pubkey,
    pub request: Pubkey,
    pub request_hash: [u8; 32],
}

#[event]
pub struct ValidationResponseEv {
    pub validator: Pubkey,
    pub agent: Pubkey,
    pub request: Pubkey,
    pub response: u8,
    pub tag: [u8; 32],
}
