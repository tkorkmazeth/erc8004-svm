import { AnchorProvider, Program, Idl, BN } from "@coral-xyz/anchor";
import {
  Connection,
  PublicKey,
  SystemProgram,
  Ed25519Program,
  TransactionInstruction,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import keccak from "keccak";
import idl from "./idl.json" assert { type: "json" };
import { PROGRAM_ID, seeds, FeedbackAuth, encodeFeedbackAuth } from "./types";

export function createClient(
  connection: Connection,
  wallet: AnchorProvider["wallet"]
) {
  const provider = new AnchorProvider(
    connection,
    wallet,
    AnchorProvider.defaultOptions()
  );
  const program = new Program(idl as Idl, PROGRAM_ID, provider);

  return {
    program,
    async initPlatform() {
      const [platform] = PublicKey.findProgramAddressSync(
        seeds.platform(),
        PROGRAM_ID
      );
      await program.methods
        .initPlatform()
        .accounts({
          platform,
          authority: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      return { platform };
    },
    async registerAgent(platform: PublicKey, tokenUri: string) {
      const platformAcc = await program.account.platform.fetch(platform);
      const agentId = BigInt((platformAcc.agentCounter as BN).toString());
      const [agent] = PublicKey.findProgramAddressSync(
        seeds.agent(platform, agentId),
        PROGRAM_ID
      );
      await program.methods
        .agentRegister(tokenUri)
        .accounts({
          platform,
          authority: wallet.publicKey,
          owner: wallet.publicKey,
          agent,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      return { agent, agentId };
    },
    async setMetadata(agent: PublicKey, key: string, value: Uint8Array) {
      const keyHash = keccak("keccak256").update(key).digest();
      const [meta] = PublicKey.findProgramAddressSync(
        seeds.meta(agent, keyHash),
        PROGRAM_ID
      );
      await program.methods
        .agentSetMetadata(key, [...value], Array.from(keyHash))
        .accounts({
          agent,
          owner: wallet.publicKey,
          meta,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      return { meta };
    },
    async giveFeedbackEd25519(params: {
      agent: PublicKey;
      score: number;
      tag1: Uint8Array;
      tag2: Uint8Array;
      fileUri: string;
      fileHash: Uint8Array;
      auth: FeedbackAuth;
      signature: Uint8Array;
    }) {
      const { agent, score, tag1, tag2, fileUri, fileHash, auth, signature } =
        params;

      if (tag1.length !== 32 || tag2.length !== 32) {
        throw new Error("tags must be 32-byte arrays");
      }
      if (fileHash.length !== 32) {
        throw new Error("fileHash must be 32 bytes");
      }
      if (signature.length !== 64) {
        throw new Error("ed25519 signature must be 64 bytes");
      }
      if (!auth.client.equals(wallet.publicKey)) {
        throw new Error("auth client must match wallet");
      }
      if (score < 0 || score > 100) {
        throw new Error("score must be in 0..=100");
      }

      const agentAccount = await program.account.agent.fetch(agent);
      const agentId = BigInt((agentAccount.id as BN).toString());
      if (auth.agentId !== agentId) {
        throw new Error("auth agentId must match on-chain agent id");
      }

      const [idx] = PublicKey.findProgramAddressSync(
        seeds.idx(agent, wallet.publicKey),
        PROGRAM_ID
      );
      const idxAccount = await program.account.clientIndex.fetchNullable(idx);
      const lastIndex = idxAccount
        ? BigInt((idxAccount.lastIndex as BN).toString())
        : 0n;
      const nextIndex = lastIndex + 1n;

      const [feedback] = PublicKey.findProgramAddressSync(
        seeds.fb(agent, wallet.publicKey, nextIndex),
        PROGRAM_ID
      );

      const authStructBytes = encodeFeedbackAuth(auth);
      const digest = keccak("keccak256").update(authStructBytes).digest();
      const edIx = buildEd25519Ix(
        Uint8Array.from(digest),
        auth.signer,
        signature
      );

      await program.methods
        .giveFeedbackEd25519(
          score,
          Array.from(tag1),
          Array.from(tag2),
          fileUri,
          Array.from(fileHash),
          Array.from(authStructBytes),
          Array.from(signature),
          new BN(nextIndex.toString())
        )
        .accounts({
          agent,
          client: wallet.publicKey,
          idx,
          feedback,
          ixSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          systemProgram: SystemProgram.programId,
        })
        .preInstructions([edIx])
        .rpc();

      return { feedback, index: nextIndex };
    },
  };
}

export function buildEd25519Ix(
  digest32: Uint8Array,
  signer: PublicKey,
  sig64: Uint8Array
): TransactionInstruction {
  if (digest32.length !== 32) {
    throw new Error("digest must be 32 bytes");
  }
  if (sig64.length !== 64) {
    throw new Error("ed25519 signature must be 64 bytes");
  }

  return Ed25519Program.createInstructionWithPublicKey({
    publicKey: signer.toBytes(),
    message: digest32,
    signature: sig64,
  });
}
