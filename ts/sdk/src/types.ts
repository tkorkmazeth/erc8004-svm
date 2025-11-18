import { PublicKey } from "@solana/web3.js";
export const PROGRAM_ID = new PublicKey(
  "F3471nQ1BYRVUL2RUGRfC5JToakHkweBmLAMoMFBjo9d"
);

const leBytes = (value: bigint) => {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(value);
  return buf;
};

export const seeds = {
  platform: () => [Buffer.from("platform")],
  agent: (platform: PublicKey, agentId: bigint) => [
    Buffer.from("agent"),
    platform.toBuffer(),
    leBytes(agentId),
  ],
  meta: (agentPda: PublicKey, keyHash: Uint8Array) => [
    Buffer.from("meta"),
    agentPda.toBuffer(),
    Buffer.from(keyHash),
  ],
  idx: (agentPda: PublicKey, client: PublicKey) => [
    Buffer.from("idx"),
    agentPda.toBuffer(),
    client.toBuffer(),
  ],
  fb: (agentPda: PublicKey, client: PublicKey, index: bigint) => [
    Buffer.from("fb"),
    agentPda.toBuffer(),
    client.toBuffer(),
    leBytes(index),
  ],
  vreq: (agentPda: PublicKey, requestHashPubkey: PublicKey) => [
    Buffer.from("vreq"),
    agentPda.toBuffer(),
    requestHashPubkey.toBuffer(),
  ],
  vres: (requestPda: PublicKey) => [Buffer.from("vres"), requestPda.toBuffer()],
};

const wordFromU64 = (value: bigint) => {
  const buf = Buffer.alloc(32);
  buf.writeBigUInt64BE(value, 24);
  return buf;
};

export interface FeedbackAuth {
  agentId: bigint;
  client: PublicKey;
  indexLimit: bigint;
  expiry: bigint;
  chainId: bigint;
  identityRegistry: PublicKey;
  signer: PublicKey;
}

export function encodeFeedbackAuth(auth: FeedbackAuth): Buffer {
  return Buffer.concat([
    wordFromU64(auth.agentId),
    auth.client.toBuffer(),
    wordFromU64(auth.indexLimit),
    wordFromU64(auth.expiry),
    wordFromU64(auth.chainId),
    auth.identityRegistry.toBuffer(),
    auth.signer.toBuffer(),
  ]);
}
