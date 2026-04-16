#[cfg(feature = "v3")]
use paseto_wasm::v3;
#[cfg(feature = "v4")]
use paseto_wasm::v4;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[cfg(feature = "v4")]
#[wasm_bindgen_test]
fn test_v4_local() {
    let key = v4::generate_v4_local_key();
    let message = JsValue::from_str("hello world");

    let token = v4::encrypt_v4_local(&key, message.clone(), None, None).expect("encrypt failed");
    let decrypted = v4::decrypt_v4_local(&key, &token, None, None).expect("decrypt failed");

    assert_eq!(decrypted, "hello world");
}

#[cfg(feature = "v4")]
#[wasm_bindgen_test]
fn test_v4_local_with_footer() {
    let key = v4::generate_v4_local_key();
    let message = JsValue::from_str("hello footer");
    let footer = Some("footer".to_string());

    let token =
        v4::encrypt_v4_local(&key, message.clone(), footer.clone(), None).expect("encrypt failed");
    let decrypted = v4::decrypt_v4_local(&key, &token, footer, None).expect("decrypt failed");

    assert_eq!(decrypted, "hello footer");
}

#[cfg(feature = "v4")]
#[wasm_bindgen_test]
fn test_v4_public() {
    let key_pair = v4::generate_v4_public_key_pair();
    let message = JsValue::from_str("hello public");

    let token =
        v4::sign_v4_public(&key_pair.secret(), message.clone(), None, None).expect("sign failed");
    let verified =
        v4::verify_v4_public(&key_pair.public(), &token, None, None).expect("verify failed");

    assert_eq!(verified, "hello public");
}

#[cfg(feature = "v4")]
#[wasm_bindgen_test]
fn test_v4_paserk() {
    let key = v4::generate_v4_local_key();
    let paserk_local = v4::key_to_paserk_local(&key).expect("paserk local");
    assert!(paserk_local.starts_with("k4.local."));
    let key_back = v4::paserk_local_to_key(&paserk_local).expect("key back");
    assert_eq!(key, key_back);

    let kid = v4::get_local_key_id(&key).expect("kid");
    assert!(kid.starts_with("k4.lid."));

    let kp = v4::generate_v4_public_key_pair();
    let paserk_pub = v4::key_to_paserk_public(&kp.public()).expect("paserk public");
    assert!(paserk_pub.starts_with("k4.public."));
    let pub_back = v4::paserk_public_to_key(&paserk_pub).expect("pub back");
    assert_eq!(kp.public(), pub_back);

    let paserk_secret = v4::key_to_paserk_secret(&kp.secret()).expect("paserk secret");
    assert!(paserk_secret.starts_with("k4.secret."));
    let secret_back = v4::paserk_secret_to_key(&paserk_secret).expect("secret back");
    assert_eq!(kp.secret(), secret_back);

    let pid = v4::get_public_key_id(&kp.public()).expect("pid");
    assert!(pid.starts_with("k4.pid."));

    let sid = v4::get_secret_key_id(&kp.secret()).expect("sid");
    assert!(sid.starts_with("k4.sid."));
}

#[cfg(feature = "v3")]
#[wasm_bindgen_test]
fn test_v3_local() {
    let key = v3::generate_v3_local_key();
    let message = JsValue::from_str("hello v3");

    let token = v3::encrypt_v3_local(&key, message.clone(), None, None).expect("encrypt failed");
    let decrypted = v3::decrypt_v3_local(&key, &token, None, None).expect("decrypt failed");

    assert_eq!(decrypted, "hello v3");
}

#[cfg(feature = "v3")]
#[wasm_bindgen_test]
fn test_v3_public() {
    let key_pair = v3::generate_v3_public_key_pair();
    let message = JsValue::from_str("hello v3 public");

    let token =
        v3::sign_v3_public(&key_pair.secret(), message.clone(), None, None).expect("sign failed");
    let verified =
        v3::verify_v3_public(&key_pair.public(), &token, None, None).expect("verify failed");

    assert_eq!(verified, "hello v3 public");
}

#[cfg(feature = "v3")]
#[wasm_bindgen_test]
fn test_v3_paserk() {
    let key = v3::generate_v3_local_key();
    let paserk_local = v3::key_to_paserk_v3_local(&key).expect("paserk local");
    assert!(paserk_local.starts_with("k3.local."));
    let key_back = v3::paserk_v3_local_to_key(&paserk_local).expect("key back");
    assert_eq!(key, key_back);

    let kid = v3::get_v3_local_key_id(&key).expect("kid");
    assert!(kid.starts_with("k3.lid."));

    let kp = v3::generate_v3_public_key_pair();
    let paserk_pub = v3::key_to_paserk_v3_public(&kp.public()).expect("paserk public");
    assert!(paserk_pub.starts_with("k3.public."));
    let pub_back = v3::paserk_v3_public_to_key(&paserk_pub).expect("pub back");
    assert_eq!(kp.public(), pub_back);

    let paserk_secret = v3::key_to_paserk_v3_secret(&kp.secret()).expect("paserk secret");
    assert!(paserk_secret.starts_with("k3.secret."));
    let secret_back = v3::paserk_v3_secret_to_key(&paserk_secret).expect("secret back");
    assert_eq!(kp.secret(), secret_back);

    let pid = v3::get_v3_public_key_id(&kp.public()).expect("pid");
    assert!(pid.starts_with("k3.pid."));

    let sid = v3::get_v3_secret_key_id(&kp.secret()).expect("sid");
    assert!(sid.starts_with("k3.sid."));
}

#[cfg(feature = "v3")]
#[wasm_bindgen_test]
fn test_v3_local_with_footer() {
    let key = v3::generate_v3_local_key();
    let message = JsValue::from_str("hello v3 with footer");
    let footer = Some("footer data".to_string());

    let token =
        v3::encrypt_v3_local(&key, message.clone(), footer.clone(), None).expect("encrypt failed");
    let decrypted = v3::decrypt_v3_local(&key, &token, footer, None).expect("decrypt failed");

    assert_eq!(decrypted, "hello v3 with footer");
}

#[cfg(feature = "v3")]
#[wasm_bindgen_test]
fn test_v3_public_with_footer() {
    let key_pair = v3::generate_v3_public_key_pair();
    let message = JsValue::from_str("hello v3 public with footer");
    let footer = Some("v3 footer".to_string());

    let token = v3::sign_v3_public(&key_pair.secret(), message.clone(), footer.clone(), None)
        .expect("sign failed");
    let verified =
        v3::verify_v3_public(&key_pair.public(), &token, footer, None).expect("verify failed");

    assert_eq!(verified, "hello v3 public with footer");
}

#[cfg(feature = "v3")]
#[wasm_bindgen_test]
fn test_v3_public_wrong_key_fails() {
    let key_pair1 = v3::generate_v3_public_key_pair();
    let key_pair2 = v3::generate_v3_public_key_pair();
    let message = JsValue::from_str("test message");

    let token = v3::sign_v3_public(&key_pair1.secret(), message, None, None).expect("sign failed");

    // Verification with wrong key should fail
    let result = v3::verify_v3_public(&key_pair2.public(), &token, None, None);
    assert!(result.is_err());
}
