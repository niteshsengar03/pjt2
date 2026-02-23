import express from "express";
import { createServer as createViteServer } from "vite";
import crypto from "crypto";
import { P, G, modPow, randomBigInt } from "./src/cryptoUtils.ts";

function logSection(title: string) {
  console.log("\n" + "=".repeat(60));
  console.log(`🧠 ${title}`);
  console.log("=".repeat(60));
}

function short(v: bigint | string, len = 40) {
  const s = v.toString();
  return s.length > len ? s.slice(0, len) + "..." : s;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  /**
   * IN-MEMORY STORAGE (Simulating MongoDB and Redis)
   */
  // Users: email -> { publicKey: bigint }
  const users = new Map<string, { publicKey: bigint }>();
  // Challenges: email -> { challenge: bigint, commitment: bigint, expires: number }
  const activeChallenges = new Map<
    string,
    { challenge: bigint; commitment: bigint; expires: number }
  >();

  // --- API Routes ---

  /**
   * SIGNUP: Store the public key P = g^x mod p
   */
  app.post("/api/signup", (req, res) => {
    const { email, publicKey } = req.body;
    if (!email || !publicKey)
      return res.status(400).json({ error: "Missing fields" });

    if (users.has(email)) return res.status(400).json({ error: "User exists" });

    logSection("SIGNUP REQUEST");
    console.log("Email:", email);
    console.log("Received Public Key (P = g^x mod p)");
    console.log("P =", short(publicKey));

    users.set(email, { publicKey: BigInt(publicKey) });
    console.log(
      `[Signup] ${email} registered with P: ${publicKey.substring(0, 20)}...`,
    );
    console.log("User stored successfully.");
    console.log("Current user count:", users.size);
    res.json({ success: true });
  });

  /**
   * LOGIN STEP 1: Receive commitment R = g^r mod p
   * Return a random challenge c
   */
  app.post("/api/login/commit", (req, res) => {
    const { email, R } = req.body;
    const user = users.get(email);
    if (!user) return res.status(404).json({ error: "User not found" });

    logSection("LOGIN STEP 1 — COMMITMENT");

    console.log("Email:", email);
    console.log("Commitment R = g^r mod p");
    console.log("R =", short(R));
    // Generate a 256-bit random challenge 'c'
    // In a real app, 'c' should be large enough to prevent birthday attacks
    const challenge = randomBigInt(2n ** 256n);

    // Store challenge and commitment in "Redis" (expires in 2 minutes)

    console.log("Generated Challenge c:");
    console.log("c =", short(challenge));

    activeChallenges.set(email, {
      challenge,
      commitment: BigInt(R),
      expires: Date.now() + 120000,
    });

    console.log("Challenge stored (expires in 2 mins)");

    res.json({ challenge: challenge.toString() });
  });

  /**
   * LOGIN STEP 2: Verify response s = r + c*x mod (p-1)
   * Verification: g^s == R * P^c mod p
   */
  app.post("/api/login/verify", (req, res) => {
    const { email, s } = req.body;
    const user = users.get(email);
    const authSession = activeChallenges.get(email);

    if (!user || !authSession || authSession.expires < Date.now()) {
      return res.status(400).json({ error: "Session expired or invalid" });
    }

    logSection("LOGIN STEP 2 — VERIFY PROOF");

    const S = BigInt(s);
    const R = authSession.commitment;
    const C = authSession.challenge;
    const P_val = user.publicKey;

    console.log("Email:", email);
    console.log("Received s =", short(S));
    console.log("Stored R =", short(R));
    console.log("Challenge c =", short(C));
    console.log("Public key P =", short(P_val));

    console.log("\n--- Computing Verification ---");

    /**
     * SCHNORR VERIFICATION MATH:
     * Left Side: g^s mod p
     * Right Side: (R * (P^c mod p)) mod p
     */
    const leftSide = modPow(G, S, P);
    const rightSide = (R * modPow(P_val, C, P)) % P;

    console.log("Left  (g^s mod p) =", short(leftSide));
    console.log("Right (R * P^c mod p) =", short(rightSide));

    // Clean up challenge after one attempt (Prevent Replay)
    activeChallenges.delete(email);

    if (leftSide === rightSide) {
      console.log("\n✅ Proof VERIFIED — user owns secret x");

      // In a real app, issue a JWT here
      const token = crypto.randomBytes(32).toString("hex");
      console.log(`[Login] ${email} verified successfully!`);
      res.json({
        success: true,
        token,
        message: "Zero-Knowledge Proof Verified!",
      });
    } else {
      console.log("\n❌ Verification FAILED");
      console.log(`[Login] ${email} verification failed.`);
      res.status(401).json({ error: "Cryptographic proof invalid" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
