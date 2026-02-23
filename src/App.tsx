/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import {
  Shield,
  Lock,
  Mail,
  Key,
  CheckCircle2,
  AlertCircle,
  Loader2,
  ArrowRight,
  Fingerprint,
  Cpu,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { P, G, modPow, randomBigInt } from "./cryptoUtils";

// --- Cryptography Helpers (Browser Side) ---

/**
 * STEP 1: Generate a Schnorr-compatible key pair.
 * Private key x is a random number.
 * Public key P = g^x mod p.
 */
async function generateSchnorrKeyPair() {
  const x = randomBigInt(P - 1n);
  const publicKey = modPow(G, x, P);
  return {
    privateKey: x.toString(),
    publicKey: publicKey.toString(),
  };
}

/**
 * STEP 2: Encrypt the Private Key using the user's passphrase.
 * Uses AES-GCM with PBKDF2 key derivation.
 */
async function encryptPrivateKey(privateKey: string, passphrase: string) {
  const encoder = new TextEncoder();
  const passphraseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const key = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encoder.encode(privateKey),
  );

  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    salt: btoa(String.fromCharCode(...salt)),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

/**
 * STEP 3: Decrypt the Private Key.
 */
async function decryptPrivateKey(
  encryptedData: { encrypted: string; salt: string; iv: string },
  passphrase: string,
) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const passphraseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const salt = new Uint8Array(
    atob(encryptedData.salt)
      .split("")
      .map((c) => c.charCodeAt(0)),
  );
  const iv = new Uint8Array(
    atob(encryptedData.iv)
      .split("")
      .map((c) => c.charCodeAt(0)),
  );
  const encrypted = new Uint8Array(
    atob(encryptedData.encrypted)
      .split("")
      .map((c) => c.charCodeAt(0)),
  );

  const key = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encrypted,
    );
    return decoder.decode(decrypted);
  } catch (e) {
    throw new Error("Invalid passphrase - could not unlock your secure key.");
  }
}

// --- Components ---

export default function App() {
  const [mode, setMode] = useState<"signup" | "signin" | "success">("signup");
  const [email, setEmail] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setStatus("Generating Schnorr key pair...");

    try {
      console.log("\n==================================================");
      console.log("🧠 FRONTEND — SIGNUP START");
      console.log("==================================================");

      console.log("📧 User Email:", email);

      // -----------------------------
      // STEP 1 — KEY GENERATION
      // -----------------------------

      const { privateKey, publicKey } = await generateSchnorrKeyPair();

      console.log("\n🔑 STEP 1 — KEY GENERATION");
      console.log("Private key x (client only) =", privateKey);
      console.log("Public key P = g^x mod p =", publicKey);

      // -----------------------------
      // STEP 2 — ENCRYPT PRIVATE KEY
      // -----------------------------
      setStatus("Encrypting private key locally...");
      const encryptedData = await encryptPrivateKey(privateKey, passphrase);

      console.log("\n🔐 STEP 2 — LOCAL ENCRYPTION");
      console.log("Encrypted private key =", encryptedData.encrypted);
      console.log("Salt =", encryptedData.salt);
      console.log("IV =", encryptedData.iv);

      // -----------------------------
      // STEP 3 — STORE LOCALLY
      // -----------------------------

      // Store encrypted private key in browser (IndexedDB would be better, but LocalStorage is easier for demo)
      localStorage.setItem(
        `schnorr_key_${email}`,
        JSON.stringify(encryptedData),
      );

      console.log("\n💾 STEP 3 — LOCAL STORAGE");
      console.log("Stored encrypted key under:");
      console.log(`schnorr_key_${email}`);
      console.log("⚠️ Only encrypted key stored (private key NOT stored)");

      // -----------------------------
      // STEP 4 — SEND PUBLIC KEY
      // -----------------------------

      setStatus("Registering public key with server...");

      console.log("\n🌐 STEP 4 — SERVER REQUEST");
      console.log("Sending ONLY public key to backend");
      console.log("Payload =", { email, publicKey });

      const response = await fetch("/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, publicKey }),
      });

      const data = await response.json();

      console.log("\n📥 BACKEND RESPONSE");
      console.log(data);

      if (!response.ok) throw new Error(data.error || "Signup failed");

      console.log("\n✅ FRONTEND SIGNUP COMPLETE");

      setStatus("Signup complete!");
      setTimeout(() => setMode("signin"), 1000);
    } catch (err: any) {
      console.error("\n❌ FRONTEND SIGNUP ERROR:", err.message);

      setError(err.message);
    } finally {
      setLoading(false);
      setStatus(null);
    }
  };

  const handleSignin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setStatus("Unlocking local private key...");

    try {
      console.log("\n==================================================");
      console.log("🧠 FRONTEND — LOGIN START (PROVER)");
      console.log("==================================================");

      console.log("📧 Email:", email);

      // 1. Unlock private key
      const storedData = localStorage.getItem(`schnorr_key_${email}`);
      if (!storedData)
        throw new Error("No key found for this email on this device.");
      const encryptedData = JSON.parse(storedData);
      const privateKeyStr = await decryptPrivateKey(encryptedData, passphrase);
      const x = BigInt(privateKeyStr);

      console.log("\n🔓 STEP 1 — UNLOCK PRIVATE KEY");
      console.log("Encrypted key found in localStorage");
      console.log("Private key x (decrypted locally) =", privateKeyStr);
      console.log("⚠️ Private key never sent to server");

      // 2. Commitment: Choose random r, compute R = g^r mod p
      setStatus("Generating ZKP commitment...");
      const r = randomBigInt(P - 1n);
      const R = modPow(G, r, P);

      console.log("\n🎲 STEP 2 — GENERATE COMMITMENT");
      console.log("Random nonce r =", r.toString());
      console.log("Commitment R = g^r mod p =", R.toString());
      console.log("Sending R to backend...");

      // 3. Send R to server, get challenge c
      setStatus("Requesting challenge from server...");
      const commitRes = await fetch("/api/login/commit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, R: R.toString() }),
      });
      const commitData = await commitRes.json();
      if (!commitRes.ok) throw new Error(commitData.error || "Login failed");
      const c = BigInt(commitData.challenge);

      console.log("\n🌐 STEP 3 — CHALLENGE RECEIVED");
      console.log("Challenge c from server =", c.toString());

      // 4. Compute response: s = r + c*x mod (p-1)
      setStatus("Computing Schnorr response...");
      const s = (r + c * x) % (P - 1n);

      console.log("\n🧮 STEP 4 — COMPUTE RESPONSE");
      console.log("Formula: s = r + c*x mod (p-1)");
      console.log("Computed s =", s.toString());
      console.log("Sending s to backend for verification...");

      // 5. Send s to server for verification
      setStatus("Verifying proof on server...");
      const verifyRes = await fetch("/api/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, s: s.toString() }),
      });

      const verifyData = await verifyRes.json();
      if (!verifyRes.ok)
        throw new Error(verifyData.error || "ZKP Verification failed");
      console.log("\n📥 STEP 5 — VERIFICATION RESULT");
      console.log("Server response:", verifyData);
      console.log("🎉 ZKP login successful");
      setMode("success");
    } catch (err: any) {
      console.error("\n❌ FRONTEND LOGIN ERROR:", err.message);
      setError(err.message);
    } finally {
      setLoading(false);
      setStatus(null);
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-zinc-100 font-sans flex items-center justify-center p-4">
      {/* Background Glows */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-emerald-500/10 blur-[120px] rounded-full" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-blue-500/10 blur-[120px] rounded-full" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md relative z-10"
      >
        <div className="bg-zinc-900/40 backdrop-blur-2xl border border-white/5 rounded-[2.5rem] p-10 shadow-3xl">
          <div className="flex flex-col items-center mb-10 text-center">
            <div className="w-20 h-20 bg-gradient-to-br from-emerald-500/20 to-blue-500/20 rounded-3xl flex items-center justify-center mb-6 border border-white/10 shadow-inner">
              <Shield className="w-10 h-10 text-emerald-400" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-b from-white to-zinc-500 bg-clip-text text-transparent">
              Schnorr ZKP Auth
            </h1>
            <p className="text-zinc-500 text-sm mt-3 font-medium">
              {mode === "signup"
                ? "Zero-knowledge registration"
                : mode === "signin"
                  ? "Cryptographic identity verification"
                  : "Access Granted"}
            </p>
          </div>

          <AnimatePresence mode="wait">
            {mode === "success" ? (
              <motion.div
                key="success"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="flex flex-col items-center py-6"
              >
                <div className="w-24 h-24 bg-emerald-500 rounded-full flex items-center justify-center mb-8 shadow-2xl shadow-emerald-500/40 relative">
                  <div className="absolute inset-0 rounded-full animate-ping bg-emerald-500/20" />
                  <CheckCircle2 className="w-12 h-12 text-white" />
                </div>
                <h2 className="text-2xl font-bold mb-3">Verified</h2>
                <p className="text-zinc-500 text-center mb-10 leading-relaxed">
                  The server verified your identity using a Schnorr
                  Zero-Knowledge Proof. Your secret never left your device.
                </p>
                <button
                  onClick={() => setMode("signin")}
                  className="px-8 py-3 bg-zinc-800 hover:bg-zinc-700 rounded-2xl text-sm font-semibold transition-all border border-white/5"
                >
                  Sign Out
                </button>
              </motion.div>
            ) : (
              <motion.form
                key={mode}
                initial={{ opacity: 0, x: mode === "signup" ? -20 : 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: mode === "signup" ? 20 : -20 }}
                onSubmit={mode === "signup" ? handleSignup : handleSignin}
                className="space-y-6"
              >
                <div className="space-y-3">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-[0.2em] ml-1">
                    Identity
                  </label>
                  <div className="relative group">
                    <Mail className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 text-zinc-600 group-focus-within:text-emerald-500 transition-colors" />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full bg-black/40 border border-white/5 rounded-2xl py-4 pl-14 pr-6 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/40 transition-all placeholder:text-zinc-800 text-zinc-200"
                      placeholder="Enter your email"
                    />
                  </div>
                </div>

                <div className="space-y-3">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-[0.2em] ml-1">
                    Local Unlock
                  </label>
                  <div className="relative group">
                    <Lock className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 text-zinc-600 group-focus-within:text-emerald-500 transition-colors" />
                    <input
                      type="password"
                      required
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                      className="w-full bg-black/40 border border-white/5 rounded-2xl py-4 pl-14 pr-6 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/40 transition-all placeholder:text-zinc-800 text-zinc-200"
                      placeholder="Passphrase"
                    />
                  </div>
                </div>

                {error && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-red-500/5 border border-red-500/10 rounded-2xl p-4 flex items-start gap-4"
                  >
                    <AlertCircle className="w-5 h-5 text-red-500 shrink-0" />
                    <p className="text-xs text-red-400/80 leading-relaxed font-medium">
                      {error}
                    </p>
                  </motion.div>
                )}

                {status && (
                  <div className="flex items-center gap-3 text-xs text-emerald-500/60 font-medium ml-1">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    {status}
                  </div>
                )}

                <button
                  disabled={loading}
                  className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed text-black font-bold py-4 rounded-2xl shadow-xl shadow-emerald-500/20 transition-all flex items-center justify-center gap-3 group"
                >
                  {loading ? (
                    <Loader2 className="w-6 h-6 animate-spin" />
                  ) : (
                    <>
                      <span className="tracking-tight">
                        {mode === "signup" ? "Initialize ZKP" : "Verify Proof"}
                      </span>
                      <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                    </>
                  )}
                </button>

                <div className="pt-6 text-center">
                  <button
                    type="button"
                    onClick={() =>
                      setMode(mode === "signup" ? "signin" : "signup")
                    }
                    className="text-zinc-600 hover:text-zinc-400 text-xs font-semibold transition-colors tracking-tight"
                  >
                    {mode === "signup"
                      ? "Switch to Secure Login"
                      : "Create New ZKP Identity"}
                  </button>
                </div>
              </motion.form>
            )}
          </AnimatePresence>
        </div>

        {/* Technical Details Footer */}
        <div className="mt-10 grid grid-cols-2 gap-6">
          <div className="bg-zinc-900/20 border border-white/5 rounded-3xl p-6 backdrop-blur-sm">
            <div className="flex items-center gap-3 mb-3">
              <Cpu className="w-5 h-5 text-emerald-500/50" />
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">
                Schnorr ZKP
              </span>
            </div>
            <p className="text-[10px] text-zinc-600 leading-relaxed font-medium">
              Uses modular arithmetic: g^s ≡ R · P^c (mod p). Proves knowledge
              of secret 'x' without revealing it.
            </p>
          </div>
          <div className="bg-zinc-900/20 border border-white/5 rounded-3xl p-6 backdrop-blur-sm">
            <div className="flex items-center gap-3 mb-3">
              <Fingerprint className="w-5 h-5 text-blue-500/50" />
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">
                Local Shield
              </span>
            </div>
            <p className="text-[10px] text-zinc-600 leading-relaxed font-medium">
              Private key is AES-GCM encrypted. Decrypted only in memory during
              proof generation.
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
