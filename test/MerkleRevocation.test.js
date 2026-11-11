/**
 * MerkleRevocation.test.js
 *
 * Run: npx hardhat test test/MerkleRevocation.test.js
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const {
  MAX_ID, rangeLeaf, buildRevocationTree, getNonRevocationProof, proofForLeaf, isRevoked,
} = require("../scripts/merkleHelper");

const REVOKED = [3n, 7n, 9n, 20n, 21n, 1000n];

async function deploy(root) {
  const merkle = await (await ethers.getContractFactory("MerkleRevocation")).deploy(root);
  await merkle.waitForDeployment();
  return merkle;
}

async function verifyTx(merkle, id, { lo, hi, proof }) {
  const receipt = await (await merkle.verifyNonRevocation(id, lo, hi, proof)).wait();
  const log = receipt.logs.map((l) => merkle.interface.parseLog(l)).find((l) => l && l.name === "Verified");
  return { notRevoked: log.args.notRevoked, gas: Number(receipt.gasUsed) };
}

describe("MerkleRevocation (sorted range-leaf tree)", function () {
  let owner, other, merkle, tree;

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();
    tree = buildRevocationTree(REVOKED);
    merkle = await deploy(tree.root);
  });

  describe("encoding", function () {
    it("MAX_ID and the leaf hash match the off-chain helper", async function () {
      expect(await merkle.MAX_ID()).to.equal(MAX_ID);
      expect(await merkle.rangeLeaf(3, 7)).to.equal("0x" + rangeLeaf(3n, 7n).toString("hex"));
    });
  });

  describe("updateRoot()", function () {
    it("reverts when called by non-owner", async function () {
      await expect(merkle.connect(other).updateRoot(ethers.ZeroHash)).to.be.revertedWithCustomError(merkle, "OnlyOwner");
    });

    it("updates the stored root and emits RootUpdated", async function () {
      const next = buildRevocationTree([...REVOKED, 5n]).root;
      await expect(merkle.updateRoot(next)).to.emit(merkle, "RootUpdated").withArgs(next);
      expect(await merkle.root()).to.equal(next);
    });
  });

  describe("verifyNonRevocation() – non-revoked IDs", function () {
    it("returns true with a valid proof", async function () {
      for (const id of [1n, 2n, 5n, 8n, 10n, 19n, 500n, 1001n, MAX_ID - 1n]) {
        const p = getNonRevocationProof(tree, id);
        expect((await verifyTx(merkle, id, p)).notRevoked, `id ${id}`).to.equal(true);
      }
    });

    it("returns false without a valid proof", async function () {
      const id = 5n;
      const good = getNonRevocationProof(tree, id);
      // empty proof, zero-filled proof of the right depth, and a tampered sibling
      expect(await merkle.checkNonRevocation(id, good.lo, good.hi, [])).to.equal(false);
      const zeros = good.proof.map(() => ethers.ZeroHash);
      expect(await merkle.checkNonRevocation(id, good.lo, good.hi, zeros)).to.equal(false);
      const tampered = [...good.proof];
      tampered[0] = ethers.keccak256(tampered[0]);
      expect((await verifyTx(merkle, id, { ...good, proof: tampered })).notRevoked).to.equal(false);
    });

    it("returns false for a proof made for a different range", async function () {
      const other10 = getNonRevocationProof(tree, 10n); // range (9, 20)
      expect(await merkle.checkNonRevocation(5n, other10.lo, other10.hi, other10.proof)).to.equal(false);
    });

    it("returns false for a stale proof after the root changes", async function () {
      const p = getNonRevocationProof(tree, 5n);
      expect((await verifyTx(merkle, 5n, p)).notRevoked).to.equal(true);
      const next = buildRevocationTree([...REVOKED, 5n]);
      await (await merkle.updateRoot(next.root)).wait();
      expect((await verifyTx(merkle, 5n, p)).notRevoked).to.equal(false);
      // 6 is still fine, with a fresh proof
      expect((await verifyTx(merkle, 6n, getNonRevocationProof(next, 6n))).notRevoked).to.equal(true);
    });
  });

  describe("verifyNonRevocation() – revoked IDs", function () {
    it("the helper cannot produce a proof", function () {
      for (const id of REVOKED) {
        expect(isRevoked(tree, id)).to.equal(true);
        expect(() => getNonRevocationProof(tree, id)).to.throw(/revoked/);
      }
    });

    it("returns false whatever proof is supplied", async function () {
      const leafCount = tree.bounds.length - 1;
      for (const id of REVOKED) {
        // every real leaf of the tree, with its valid inclusion proof
        for (let i = 0; i < leafCount; i++) {
          const p = proofForLeaf(tree, i);
          expect(await merkle.checkNonRevocation(id, p.lo, p.hi, p.proof), `id ${id}, leaf ${i}`).to.equal(false);
        }
        // made-up ranges that do contain the ID, with borrowed, empty and zero proofs
        const borrowed = proofForLeaf(tree, 0).proof;
        for (const proof of [borrowed, [], borrowed.map(() => ethers.ZeroHash)]) {
          expect(await merkle.checkNonRevocation(id, id - 1n, id + 1n, proof)).to.equal(false);
          expect(await merkle.checkNonRevocation(id, 0n, MAX_ID, proof)).to.equal(false);
        }
        // the pre-audit bug: a failing dummy proof used to count as "not revoked"
        const dummy = { lo: 0n, hi: MAX_ID, proof: borrowed.map(() => ethers.ZeroHash) };
        expect((await verifyTx(merkle, id, dummy)).notRevoked).to.equal(false);
      }
    });

    it("returns false for the sentinels and out-of-range IDs", async function () {
      const first = proofForLeaf(tree, 0);
      const last = proofForLeaf(tree, tree.bounds.length - 2);
      expect(await merkle.checkNonRevocation(0n, first.lo, first.hi, first.proof)).to.equal(false);
      expect(await merkle.checkNonRevocation(MAX_ID, last.lo, last.hi, last.proof)).to.equal(false);
      expect(await merkle.checkNonRevocation(MAX_ID + 1n, last.lo, last.hi, last.proof)).to.equal(false);
    });
  });

  describe("empty revoked set", function () {
    it("every in-range ID passes with the empty proof", async function () {
      const empty = buildRevocationTree([]);
      const m = await deploy(empty.root);
      const p = getNonRevocationProof(empty, 42n);
      expect(p.proof).to.have.length(0);
      expect((await verifyTx(m, 42n, p)).notRevoked).to.equal(true);
    });
  });

  describe("helper input checks", function () {
    it("rejects duplicates and out-of-range IDs", function () {
      expect(() => buildRevocationTree([3n, 3n])).to.throw(/duplicate/);
      expect(() => buildRevocationTree([0n])).to.throw(/outside/);
      expect(() => buildRevocationTree([MAX_ID])).to.throw(/outside/);
    });
  });

  describe("gas against tree depth", function () {
    const gasByDepth = {};

    for (const depth of [2, 4, 8, 10]) {
      it(`depth ${depth} (${2 ** depth - 1} revoked IDs)`, async function () {
        // 2^depth leaves; revoked IDs are even so that odd IDs fall in the gaps
        const revoked = Array.from({ length: 2 ** depth - 1 }, (_, i) => BigInt(2 * (i + 1)));
        const t = buildRevocationTree(revoked);
        expect(t.depth).to.equal(depth);
        const m = await deploy(t.root);

        const id = revoked[Math.floor(revoked.length / 2)] + 1n;
        const p = getNonRevocationProof(t, id);
        expect(p.proof).to.have.length(depth);
        const res = await verifyTx(m, id, p);
        expect(res.notRevoked).to.equal(true);
        gasByDepth[depth] = res.gas;
        console.log(`    depth=${depth} revoked=${revoked.length} proof_len=${p.proof.length} gas=${res.gas.toLocaleString()}`);
      });
    }

    it("gas grows with depth", function () {
      const depths = Object.keys(gasByDepth).map(Number).sort((a, b) => a - b);
      for (let i = 1; i < depths.length; i++) {
        expect(gasByDepth[depths[i]]).to.be.greaterThan(gasByDepth[depths[i - 1]]);
      }
    });
  });
});
