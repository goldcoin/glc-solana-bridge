//! Operational surface: what the relayer exposes so operators can watch it
//! (Phase 7h, ADR-0014 §13).
//!
//! # This module exposes state. It never pages anyone.
//!
//! There is deliberately no SMTP client, no PagerDuty integration, no
//! webhook, and no vendor SDK here (owner decision H2). The relayer holds no
//! alerting credentials and makes no outbound calls on their behalf;
//! operators point their existing alerting at [`health`]'s endpoint.
//!
//! That keeps secrets and vendor choices out of a process whose whole design
//! is about holding as little as possible.
//!
//! | module | responsibility |
//! |---|---|
//! | [`solvency`] | threat-model invariant #1, and the ADR-0013 D3 fee drift kept separate from it |
//! | [`metrics`] | a tiny registry and Prometheus text encoding — no dependency |
//! | [`health`] | the HTTP surface: `/health` and `/metrics` |
//! | [`collector`] | gathers a report from live database and chain state |

pub mod audit;
pub mod collector;
pub mod health;
pub mod indexer_status;
pub mod metrics;
pub mod preflight;
pub mod solvency;
pub mod withdraw_preflight;
