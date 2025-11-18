use anchor_lang::prelude::*;
use solana_program::{ed25519_program, keccak, sysvar::instructions::load_instruction_at_checked};

pub fn keccak_bytes(input: &[u8]) -> [u8; 32] {
    keccak::hash(input).0
}

pub struct FeedbackAuth {
    pub agent_id: u64,
    pub client: Pubkey,
    pub index_limit: u64,
    pub expiry: u64,
    pub chain_id: u64,
    pub identity_registry: Pubkey,
    pub signer: Pubkey,
}

pub fn decode_auth_struct(bytes: Vec<u8>) -> Result<FeedbackAuth> {
    require!(bytes.len() == 224, crate::E8004::BadSignature);
    parse_feedback_auth(&bytes)
}

fn parse_feedback_auth(bytes: &[u8]) -> Result<FeedbackAuth> {
    require!(bytes.len() == 224, crate::E8004::BadSignature);
    let mut w = bytes.chunks(32);

    let agent_id = u64::from_be_bytes(w.next().unwrap()[24..32].try_into().unwrap());
    let client = Pubkey::new_from_array(<[u8; 32]>::try_from(w.next().unwrap()).unwrap());
    let index_limit = u64::from_be_bytes(w.next().unwrap()[24..32].try_into().unwrap());
    let expiry = u64::from_be_bytes(w.next().unwrap()[24..32].try_into().unwrap());
    let chain_id = u64::from_be_bytes(w.next().unwrap()[24..32].try_into().unwrap());
    let identity_registry =
        Pubkey::new_from_array(<[u8; 32]>::try_from(w.next().unwrap()).unwrap());
    let signer = Pubkey::new_from_array(<[u8; 32]>::try_from(w.next().unwrap()).unwrap());

    Ok(FeedbackAuth {
        agent_id,
        client,
        index_limit,
        expiry,
        chain_id,
        identity_registry,
        signer,
    })
}

pub fn keccak_auth_struct(a: &FeedbackAuth) -> [u8; 32] {
    keccak::hashv(&[
        &a.agent_id.to_be_bytes(),
        a.client.as_ref(),
        &a.index_limit.to_be_bytes(),
        &a.expiry.to_be_bytes(),
        &a.chain_id.to_be_bytes(),
        a.identity_registry.as_ref(),
        a.signer.as_ref(),
    ])
    .0
}

pub fn verify_ed25519(
    digest32: &[u8; 32],
    sig64: &[u8],
    expected_signer: &Pubkey,
    ix_sysvar: &AccountInfo,
) -> bool {
    let mut i = 0usize;
    while let Ok(ix) = load_instruction_at_checked(i, ix_sysvar) {
        i += 1;
        if ix.program_id != ed25519_program::id() {
            continue;
        }

        let data = ix.data.as_slice();
        if data.len() < 2 + 2 + 2 + 2 + 2 + 2 {
            continue;
        }

        let num = data[0] as usize;
        if num != 1 {
            continue;
        }

        let sig_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let msg_len = u16::from_le_bytes([data[4], data[5]]) as usize;

        let sig_off = u16::from_le_bytes([data[6], data[7]]) as usize;
        let msg_off = u16::from_le_bytes([data[8], data[9]]) as usize;
        let pub_off = u16::from_le_bytes([data[10], data[11]]) as usize;

        if sig_off.checked_add(sig_len).unwrap_or(usize::MAX) > data.len()
            || pub_off.checked_add(32).unwrap_or(usize::MAX) > data.len()
            || msg_off.checked_add(msg_len).unwrap_or(usize::MAX) > data.len()
        {
            continue;
        }

        if sig_len != 64 || msg_len != 32 {
            continue;
        }

        let sig = &data[sig_off..sig_off + 64];
        let pubkey = &data[pub_off..pub_off + 32];
        let msg = &data[msg_off..msg_off + 32];

        if pubkey == expected_signer.as_ref() && msg == digest32 && sig == sig64 {
            return true;
        }
    }
    false
}
