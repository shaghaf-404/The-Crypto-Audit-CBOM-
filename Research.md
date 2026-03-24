# 🔐 Research: Mosca's Theorem & The Bank Migration Deadline

> **Scenario:** A hypothetical bank that stores customer health data for **30 years**
> **Goal:** Determine when they *must* begin their PQC migration — or they are already too late

---

## 📐 Mosca's Theorem — The Formula

```
If  (X + Y) > Z  →  you have a serious problem

X = How long your data must stay secret        (shelf life of secrets)
Y = How long it takes you to migrate to PQC    (migration time)
Z = When a quantum computer can break your crypto  (collapse time)
```

The logic is simple:
If the time your data needs to be safe *plus* the time to migrate
is **longer** than the time before quantum computers arrive —
you will not finish migrating before your data is already at risk.

---

## 🏦 Applying It to the Bank

### Variable X — Shelf Life of Secrets

The bank stores customer health data.
Health data is subject to HIPAA, GDPR, and local banking regulations.
Retention policy = **30 years** from the date of creation.

Data encrypted today in 2026 must still be unreadable by attackers in **2056**.

```
X = 30 years
```

### Variable Y — Migration Time

Migrating a bank's entire cryptographic infrastructure is not a simple software update.
It involves:

| Task | Estimated Time |
|---|---|
| Cryptographic inventory and audit (CBOM) | 6–12 months |
| Algorithm selection and vendor evaluation | 6–12 months |
| Development, testing, and staging | 1–2 years |
| Phased rollout across all systems | 1–2 years |
| Compliance re-certification | 6–12 months |
| **Total realistic estimate** | **4–6 years** |

Banks have complex, layered infrastructure — HSMs, core banking APIs,
TLS endpoints, database encryption, SSH access, payment rails, mobile SDKs.
None of this changes overnight.

```
Y = 5 years  (conservative midpoint estimate)
```

### Variable Z — Collapse Time

This is the unknown. Estimates from credible sources as of 2026:

| Source | Estimate |
|---|---|
| NIST (2024 PQC finalization rationale) | 2030–2035 |
| Dr. Michele Mosca (2015 survey) | 50% chance by 2031 |
| IBM Quantum Roadmap | Cryptographically relevant machine ~2030 |
| NCSC UK (2023 guidance) | Threat window opens 2030–2040 |
| Most conservative estimate | 2035 |

We will use the **optimistic conservative** estimate to give the bank the benefit of the doubt.

```
Z = 2035  →  that is 9 years from today (2026)
```

---

## ⚠️ The Calculation

```
X + Y  vs  Z

30 + 5  vs  9

35  >  9   →   CRITICAL RISK
```

The bank has already run out of comfortable time.

Even if we use the most optimistic collapse estimate (Z = 2040, 14 years away):

```
30 + 5 = 35  >  14   →   Still a serious problem
```

The data shelf life alone (30 years) dwarfs the collapse window.
This is the classic case Mosca's theorem was designed to flag.

---

## 📅 What "Migration Deadline" Actually Means Here

The migration deadline is not when they finish.
It is the **last date they can start** and still complete before Z arrives.

```
Latest start date = Z - Y = 2035 - 5 = 2030
```

If the bank does not begin full PQC migration by **2030**, they will not finish
before a quantum computer can break their existing encryption.

And here is the part that makes it worse:
An attacker can **harvest now, decrypt later**.
They do not need a quantum computer today.
They just need to store the encrypted traffic and data now,
then decrypt it in 2035 when the hardware exists.

This means any health data encrypted today with RSA or ECC
is potentially already sitting in an adversary's storage.

```
ACTUAL safe deadline = NOW
Migration should have started already.
```

---

## 🗓️ Recommended Timeline for the Bank

```
2026  →  Complete cryptographic audit (CBOM)
2027  →  Replace highest-risk systems (TLS, SSH, auth tokens)
2028  →  Replace database encryption and backup systems
2029  →  Replace internal APIs, HSM firmware, mobile SDK
2030  →  Full compliance re-certification complete
2031+ →  Monitor, patch, and operate in hybrid PQC/classical mode
```

---

## 📌 Key Takeaway

> The 30-year health data retention policy makes this bank one of the **highest-risk** 
> categories under Mosca's framework.
> 
> Unlike a company with 2-year data retention that might survive waiting until 2030,
> this bank's data encrypted *today* must still be protected in 2056.
> 
> The harvest-now-decrypt-later attack makes the real deadline **immediate**.
> Every month of delay means more long-lived sensitive data is at risk.

---

## 📚 References

- Mosca, M. (2018). *Cybersecurity in an Era with Quantum Computers: Will We Be Ready?* IEEE Security & Privacy
- NIST (2024). *Post-Quantum Cryptography Standards — FIPS 203, 204, 205*
- NCSC UK (2023). *Preparing for Quantum-Safe Cryptography*
- Utimaco. *Crypto Agility and Mosca's Theorem* — utimaco.com
