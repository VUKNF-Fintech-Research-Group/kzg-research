/**
 * MerkleRevocation.test.js
 *
 * Run: npx hardhat test test/MerkleRevocation.test.js
 */

const { expect }    = require("chai");
const { ethers }    = require("hardhat");
const { buildTree, getProof, getRevocationProof } = require("../scripts/merkleHelper");

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/** Deterministic bytes32 credential ID for index i. */
const credId = (i) => ethers.toBeHex(i + 1, 32);

/** Build a small test revocation tree with `size` leaves (must be power of 2). */
function makeTestTree(size) {
  const leaves = Array.from({ length: size }, (_, i) => credId(i));
  return { leaves, ...buildTree(leaves) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("MerkleRevocation", function () {
  let owner, other, merkle;

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("MerkleRevocation");
    merkle = await Factory.deploy(ethers.ZeroHash);
    await merkle.waitForDeployment();
  });

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  describe("updateRoot()", function () {
    it("reverts when called by non-owner", async function () {
      const newRoot = ethers.keccak256(ethers.toUtf8Bytes("test"));
      await expect(
        merkle.connect(other).updateRoot(newRoot)
      ).to.be.revertedWith("only owner");
    });

    it("updates the stored root", async function () {
      const { root } = makeTestTree(4);
      await merkle.updateRoot(root);
      expect(await merkle.root()).to.equal(root);
    });

    it("emits RootUpdated event", async function () {
      const { root } = makeTestTree(4);
      await expect(merkle.updateRoot(root))
        .to.emit(merkle, "RootUpdated")
        .withArgs(root);
    });
  });

  // -------------------------------------------------------------------------
  // verifyNonRevocation – correctness
  // -------------------------------------------------------------------------

  describe("verifyNonRevocation() – correctness", function () {
    let tree, leaves, root;

    beforeEach(async function () {
      // Build a revocation tree with 8 leaves (depth 3).
      ({ tree, leaves, root } = makeTestTree(8));
      await merkle.updateRoot(root);
    });

    it("returns true for a leaf NOT in the revocation tree", async function () {
      const notRevokedLeaf = credId(999); // outside the tree
      const dummyProof     = getRevocationProof(tree, leaves, notRevokedLeaf);
      const result = await merkle.verifyNonRevocation.staticCall(notRevokedLeaf, dummyProof);
      expect(result).to.equal(true);
    });

    it("returns false for a leaf that IS in the revocation tree", async function () {
      const revokedLeaf  = leaves[0]; // inside the tree
      const inclusionProof = getProof(tree, revokedLeaf);
      const result = await merkle.verifyNonRevocation.staticCall(revokedLeaf, inclusionProof);
      expect(result).to.equal(false);
    });

    it("returns true for a valid leaf when root has been reset to zero", async function () {
      // After reset the tree is empty – every credential is implicitly non-revoked.
      await merkle.updateRoot(ethers.ZeroHash);
      const leaf  = leaves[0];
      const proof = [];
      // keccak256(encodePacked(leaf)) will never equal ZeroHash → not in set → true
      const result = await merkle.verifyNonRevocation.staticCall(leaf, proof);
      expect(result).to.equal(true);
    });

    it("emits Verified event", async function () {
      const notRevokedLeaf = credId(999);
      const dummyProof     = getRevocationProof(tree, leaves, notRevokedLeaf);
      await expect(merkle.verifyNonRevocation(notRevokedLeaf, dummyProof))
        .to.emit(merkle, "Verified")
        .withArgs(owner.address, true, notRevokedLeaf, dummyProof.length);
    });
  });

  // -------------------------------------------------------------------------
  // Gas profiling across proof depths
  // -------------------------------------------------------------------------

  describe("verifyNonRevocation() – gas scaling", function () {
    // depths {2, 4, 8, 10, 12} → leaf counts {4, 16, 256, 1024, 4096}
    // Reduced to {2, 4, 8} in tests to keep suite fast; full sweep in benchmark.
    const TEST_DEPTHS = [2, 4, 8];

    for (const depth of TEST_DEPTHS) {
      const leafCount = 2 ** depth;

      it(`records gas for depth ${depth} (${leafCount} leaves)`, async function () {
        const leaves = Array.from({ length: leafCount }, (_, i) => credId(i));
        const { root, tree } = buildTree(leaves);
        await merkle.updateRoot(root);

        const queryLeaf  = credId(leafCount + 999); // not in tree
        const dummyProof = getRevocationProof(tree, leaves, queryLeaf);
        expect(dummyProof.length).to.equal(depth);

        const tx      = await merkle.verifyNonRevocation(queryLeaf, dummyProof);
        const receipt = await tx.wait();

        console.log(
          `    depth=${depth} leaves=${leafCount} proof_len=${dummyProof.length} ` +
          `gas=${Number(receipt.gasUsed).toLocaleString()}`
        );

        // Gas must be strictly above the fixed base cost (21k) – confirming work is done.
        expect(Number(receipt.gasUsed)).to.be.greaterThan(21_000);
      });
    }

    it("gas increases with proof depth (O(depth) scaling)", async function () {
      const gasPerDepth = {};
      for (const depth of TEST_DEPTHS) {
        const leafCount = 2 ** depth;
        const leaves    = Array.from({ length: leafCount }, (_, i) => credId(i));
        const { root, tree } = buildTree(leaves);
        await merkle.updateRoot(root);

        const queryLeaf  = credId(leafCount + 999);
        const dummyProof = getRevocationProof(tree, leaves, queryLeaf);

        const tx      = await merkle.verifyNonRevocation(queryLeaf, dummyProof);
        const receipt = await tx.wait();
        gasPerDepth[depth] = Number(receipt.gasUsed);
      }

      // Gas must be monotonically non-decreasing with depth.
      const depths = Object.keys(gasPerDepth).map(Number).sort((a, b) => a - b);
      for (let i = 1; i < depths.length; i++) {
        expect(gasPerDepth[depths[i]]).to.be.greaterThanOrEqual(gasPerDepth[depths[i - 1]]);
      }
    });
  });
});
