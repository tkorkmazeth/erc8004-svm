import { createClient } from "../ts/sdk/src/client";
import { Connection, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { AnchorProvider, Wallet } from "@coral-xyz/anchor";
import assert from "assert";

describe("erc8004-svm", () => {
  it("initializes and registers agent", async () => {
    const connection = new Connection("http://127.0.0.1:8899", "confirmed");
    const kp = Keypair.generate();
    await connection.requestAirdrop(kp.publicKey, 2 * LAMPORTS_PER_SOL);
    const provider = new AnchorProvider(
      connection,
      new Wallet(kp),
      AnchorProvider.defaultOptions()
    );
    const c = createClient(connection, provider.wallet);
    const { platform } = await c.initPlatform();
    const { agent } = await c.registerAgent(platform, "ipfs://agent.json");
    assert.ok(agent);
  });
});
