import streamlit as st
import os

# ====== IMPORT ALL REAL MODULES ======
from qkd.qkd_simulator import generate_qkd_key
from pqc.kyber_simulator import generate_pqc_shared_secret
from hybrid_key.key_fusion import derive_hybrid_key
from hybrid_key.share_manager import distribute_shares, reconstruct_from_records
from crypto_core.file_crypto import encrypt_file, decrypt_file


# ======================================================
# STREAMLIT CONFIG
# ======================================================
st.set_page_config(page_title="QuantaCrypt Dashboard", layout="wide")
st.title("🔐 QuantaCrypt — Hybrid QKD + PQC Threshold Encryption System")
st.markdown("---")

N_SHARES = 12
T_THRESHOLD = 7

# ======================================================
# SESSION STATE INITIALIZATION
# ======================================================
if "hybrid_key" not in st.session_state:
    st.session_state.hybrid_key = None

if "k_qkd" not in st.session_state:
    st.session_state.k_qkd = None

if "k_pqc" not in st.session_state:
    st.session_state.k_pqc = None

if "records" not in st.session_state:
    st.session_state.records = None

if "reconstructed_key" not in st.session_state:
    st.session_state.reconstructed_key = None

if "original_filename" not in st.session_state:
    st.session_state.original_filename = None


# ======================================================
# 1️⃣ QKD SIMULATION
# ======================================================
st.header("1️⃣ Quantum Key Distribution (QKD) Simulation")

col1, col2 = st.columns(2)

with col1:
    eve_enabled = st.checkbox("🚨 Enable Eve Attack")

    k_qkd, qber = generate_qkd_key(
        key_length_bytes=32,
        raw_bits=1024,
        eve_attack=eve_enabled,
        attack_prob=0.50 if eve_enabled else 0.0
    )

    st.session_state.k_qkd = k_qkd

    qkd_compromised = qber > 0.11

    if qkd_compromised:
        st.error(f"❌ QKD compromised (QBER={qber*100:.2f}%)")
    else:
        st.success(f"✅ QKD secure (QBER={qber*100:.2f}%)")

with col2:
    st.info("QKD → Eve raises QBER → QKD shares invalid.")
st.markdown("---")


# ======================================================
# 2️⃣ PQC SIMULATION
# ======================================================
st.header("2️⃣ PQC (Kyber Simulator)")

col1, col2 = st.columns(2)

with col1:
    k_pqc, pk, ct = generate_pqc_shared_secret(key_length_bytes=32)
    st.session_state.k_pqc = k_pqc

    st.success("✔ PQC generated successfully")

with col2:
    pqc_attack = st.checkbox("🚨 Simulate PQC Channel Attack")

    if pqc_attack:
        st.error("❌ PQC channel compromised")
    else:
        st.success("✅ PQC secure")

st.markdown("---")


# ======================================================
# 3️⃣ HYBRID KEY FUSION
# ======================================================
st.header("3️⃣ Hybrid Key Fusion (QKD ⊕ PQC)")

if st.session_state.hybrid_key is None:
    st.session_state.hybrid_key = derive_hybrid_key(
        st.session_state.k_qkd,
        st.session_state.k_pqc
    )

hybrid_key = st.session_state.hybrid_key

st.success(f"Hybrid key generated — {len(hybrid_key)} bytes")
st.code(hybrid_key.hex(), language="text")

st.markdown("---")


# ======================================================
# 4️⃣ SECRET SHARING (SHAMIR)
# ======================================================
st.header("4️⃣ Shamir Secret Sharing (12 shares, threshold 7)")

if st.session_state.records is None:
    st.session_state.records = distribute_shares(
        hybrid_key, N_SHARES, T_THRESHOLD
    )

records = st.session_state.records

qkd_records = [r for r in records if r.channel == "qkd_channel"]
pqc_records = [r for r in records if r.channel == "pqc_channel"]

col1, col2 = st.columns(2)

with col1:
    st.subheader("🔵 QKD Shares")
    qkd_compromised = qber > 0.11
    qkd_valid = 0 if qkd_compromised else len(qkd_records)
    if qkd_compromised:
        st.error("❌ QKD compromised → no valid shares")
    else:
        st.success(f"{qkd_valid} valid QKD shares")

with col2:
    st.subheader("🟢 PQC Shares")
    pqc_valid = 0 if pqc_attack else len(pqc_records)
    if pqc_attack:
        st.error("❌ PQC compromised → no valid shares")
    else:
        st.success(f"{pqc_valid} valid PQC shares")

total_valid = qkd_valid + pqc_valid
st.info(f"Total valid shares: **{total_valid} / 12**")

valid_records = []
if not qkd_compromised:
    valid_records.extend(qkd_records)
if not pqc_attack:
    valid_records.extend(pqc_records)

if total_valid >= T_THRESHOLD:
    selected = valid_records[:T_THRESHOLD]
    reconstructed_key = reconstruct_from_records(
        selected, k=T_THRESHOLD, out_length=len(hybrid_key)
    )
    st.session_state.reconstructed_key = reconstructed_key
    st.success("🎉 Reconstructed key ready for decryption!")
else:
    st.session_state.reconstructed_key = None
    st.error("❌ Not enough shares to reconstruct key")

st.markdown("---")


# ======================================================
# 5️⃣ FILE ENCRYPTION
# ======================================================
st.header("5️⃣ Encrypt File Using Hybrid Key")

uploaded_file = st.file_uploader("Upload file to encrypt:")

if uploaded_file:
    st.session_state.original_filename = uploaded_file.name

    in_path = "input_file.bin"
    with open(in_path, "wb") as f:
        f.write(uploaded_file.read())

    enc_path = "encrypted_output.bin"
    encrypt_file(in_path, enc_path, hybrid_key)

    st.success("🔐 File encrypted successfully!")
    with open(enc_path, "rb") as f:
        st.download_button("⬇ Download Encrypted File", f, "encrypted.bin")

st.markdown("---")


# ======================================================
# 6️⃣ FILE DECRYPTION (restore original file format!)
# ======================================================
st.header("6️⃣ Decrypt File (Requires ≥7 Shares)")

enc_uploaded = st.file_uploader("Upload encrypted file:", key="decrypt")

if enc_uploaded:
    if st.session_state.reconstructed_key is None:
        st.error("⛔ Cannot decrypt: Threshold NOT satisfied")
    else:
        st.success("✔ Threshold satisfied → decrypting…")

        enc_file_path = "file_to_dec.bin"
        with open(enc_file_path, "wb") as f:
            f.write(enc_uploaded.read())

        # extract original extension
        original_ext = os.path.splitext(st.session_state.original_filename)[1]
        out_path = "decrypted_output" + original_ext

        decrypt_file(enc_file_path, out_path, st.session_state.reconstructed_key)

        with open(out_path, "rb") as f:
            st.download_button(
                "⬇ Download Decrypted File",
                f,
                "decrypted" + original_ext
            )

st.caption("© 2025 QuantaCrypt — Quantum-Classical Hybrid Encryption Framework")
