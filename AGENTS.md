# TrustPass: project rules
Goal: multi-issuer, privacy-first credential network (Ethereum Sepolia).
Stack: Hardhat 3 + Solidity (Solidity tests, fuzzing), React + Vite + TypeScript + viem,
SD-JWT VC via @sd-jwt/* packages. No backend. No personal data on-chain, ever.
Rules:
- Before adding any dependency, look up its current version and docs; never guess APIs or versions. Pin exact versions.
- Contracts: custom errors, events for every state change, access control tested, NatSpec comments.
- Every contract change needs tests (unit + fuzz); run them before reporting done.
- Never commit private keys or .env; use .env.example.
- Produce a plan Artifact first; wait for my approval before writing code.
- After each phase, write a short "what changed / what is unverified" note.
- Look: white background, one blue accent (a plain institutional blue, not purple), system font, tables and forms. It should feel like a well-made university or government tool.