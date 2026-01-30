// Import V4 functions from the default build (pkg/cjs)
const {
    encrypt_v4_local,
    decrypt_v4_local,
    sign_v4_public,
    verify_v4_public,
    generate_v4_local_key,
    generate_v4_public_key_pair,
    // PASERK V4
    key_to_paserk_local,
    paserk_local_to_key,
    key_to_paserk_secret,
    paserk_secret_to_key,
    key_to_paserk_public,
    paserk_public_to_key,
    get_local_key_id,
    get_public_key_id,
    get_secret_key_id
} = require('../pkg/cjs/paseto_wasm.cjs');

// Import V3 functions from the V3 feature build (pkg/v3/cjs)
const {
    encrypt_v3_local,
    decrypt_v3_local,
    sign_v3_public,
    verify_v3_public,
    generate_v3_local_key,
    generate_v3_public_key_pair,
    // PASERK V3
    key_to_paserk_v3_local,
    paserk_v3_local_to_key,
    key_to_paserk_v3_secret,
    paserk_v3_secret_to_key,
    key_to_paserk_v3_public,
    paserk_v3_public_to_key,
    get_v3_local_key_id,
    get_v3_public_key_id,
    get_v3_secret_key_id
} = require('../pkg/v3/cjs/paseto_wasm.cjs');

const assert = require('assert');

console.log("Starting Node.js Integration Tests (Split Builds)...");

try {
    // --- V3 Local ---
    console.log("Testing V3 Local (from pkg/v3/cjs)...");
    const v3Key = generate_v3_local_key();
    const v3Payload = JSON.stringify({ sub: "node_user", admin: true });
    const v3Token = encrypt_v3_local(v3Key, v3Payload, "footer", null);
    const v3Decrypted = decrypt_v3_local(v3Key, v3Token, "footer", null);
    assert.strictEqual(v3Decrypted, v3Payload, "V3 Local Decryption failed");
    console.log("V3 Local: PASS");

    // --- V3 Public ---
    console.log("Testing V3 Public (from pkg/v3/cjs)...");
    const v3KeyPair = generate_v3_public_key_pair();
    const v3Signed = sign_v3_public(v3KeyPair.secret, v3Payload, null, null);
    const v3Verified = verify_v3_public(v3KeyPair.public, v3Signed, null, null);
    assert.strictEqual(v3Verified, v3Payload, "V3 Public Verification failed");
    console.log("V3 Public: PASS");

    // --- PASERK V3 ---
    console.log("Testing PASERK V3 (from pkg/v3/cjs)...");
    // Local
    const k3Local = key_to_paserk_v3_local(v3Key);
    assert.ok(k3Local.startsWith("k3.local."), "V3 Local PASERK format error");
    const k3LocalHex = paserk_v3_local_to_key(k3Local);
    assert.strictEqual(k3LocalHex, v3Key, "V3 Local PASERK roundtrip failed");
    const k3Lid = get_v3_local_key_id(v3Key);
    assert.ok(k3Lid.startsWith("k3.lid."), "V3 Local Key ID format error");

    // Public/Secret
    const k3Secret = key_to_paserk_v3_secret(v3KeyPair.secret);
    assert.ok(k3Secret.startsWith("k3.secret."), "V3 Secret PASERK format error");
    const k3SecretHex = paserk_v3_secret_to_key(k3Secret);
    assert.strictEqual(k3SecretHex, v3KeyPair.secret, "V3 Secret PASERK roundtrip failed");
    const k3Sid = get_v3_secret_key_id(v3KeyPair.secret);
    assert.ok(k3Sid.startsWith("k3.sid."), "V3 Secret Key ID format error");

    const k3Public = key_to_paserk_v3_public(v3KeyPair.public);
    assert.ok(k3Public.startsWith("k3.public."), "V3 Public PASERK format error");
    const k3PublicHex = paserk_v3_public_to_key(k3Public);
    assert.strictEqual(k3PublicHex, v3KeyPair.public, "V3 Public PASERK roundtrip failed");
    const k3Pid = get_v3_public_key_id(v3KeyPair.public);
    assert.ok(k3Pid.startsWith("k3.pid."), "V3 Public Key ID format error");
    console.log("PASERK V3: PASS");

    // --- V4 Local ---
    console.log("Testing V4 Local (from pkg/cjs)...");
    const v4Key = generate_v4_local_key();
    const v4Payload = "hello node v4";
    const v4Token = encrypt_v4_local(v4Key, v4Payload, null, null);
    const v4Decrypted = decrypt_v4_local(v4Key, v4Token, null, null);
    assert.strictEqual(v4Decrypted, v4Payload, "V4 Local Decryption failed");
    console.log("V4 Local: PASS");

    // --- V4 Public ---
    console.log("Testing V4 Public (from pkg/cjs)...");
    const v4KeyPair = generate_v4_public_key_pair();
    const v4Signed = sign_v4_public(v4KeyPair.secret, v4Payload, null, null);
    const v4Verified = verify_v4_public(v4KeyPair.public, v4Signed, null, null);
    assert.strictEqual(v4Verified, v4Payload, "V4 Public Verification failed");
    console.log("V4 Public: PASS");

    // --- PASERK V4 ---
    console.log("Testing PASERK V4 (from pkg/cjs)...");
    // Local
    const k4Local = key_to_paserk_local(v4Key);
    assert.ok(k4Local.startsWith("k4.local."), "V4 Local PASERK format error");
    const k4LocalHex = paserk_local_to_key(k4Local);
    assert.strictEqual(k4LocalHex, v4Key, "V4 Local PASERK roundtrip failed");
    const k4Lid = get_local_key_id(v4Key);
    assert.ok(k4Lid.startsWith("k4.lid."), "V4 Local Key ID format error");

    // Public/Secret
    const k4Secret = key_to_paserk_secret(v4KeyPair.secret);
    assert.ok(k4Secret.startsWith("k4.secret."), "V4 Secret PASERK format error");
    const k4SecretHex = paserk_secret_to_key(k4Secret);
    assert.strictEqual(k4SecretHex, v4KeyPair.secret, "V4 Secret PASERK roundtrip failed");
    const k4Sid = get_secret_key_id(v4KeyPair.secret);
    assert.ok(k4Sid.startsWith("k4.sid."), "V4 Secret Key ID format error");

    const k4Public = key_to_paserk_public(v4KeyPair.public);
    assert.ok(k4Public.startsWith("k4.public."), "V4 Public PASERK format error");
    const k4PublicHex = paserk_public_to_key(k4Public);
    assert.strictEqual(k4PublicHex, v4KeyPair.public, "V4 Public PASERK roundtrip failed");
    const k4Pid = get_public_key_id(v4KeyPair.public);
    assert.ok(k4Pid.startsWith("k4.pid."), "V4 Public Key ID format error");
    console.log("PASERK V4: PASS");

    console.log("\nAll Node.js tests passed successfully!");

} catch (e) {
    console.error("\nTEST FAILED:", e);
    process.exit(1);
}
