//! spec §6.2: the client. The `Client` app itself (state machine, paths, opens,
//! ingress glue) arrives in Task 8.3; these are its pure building blocks.

pub mod backoff;
pub mod pending;
