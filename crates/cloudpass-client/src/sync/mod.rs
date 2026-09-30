//! Talking to the sync server.
//!
//! # Why the transport is a trait
//!
//! The decisions that matter — what to commit to before a push, whether a head is
//! acceptable, how to merge what came back — are pure logic. Keeping them behind a
//! trait that only sends and receives bytes means they can be tested, including against
//! the real server, without opening a socket.
//!
//! # The rule for clients
//!
//! **Pull before push.** A push carries a signed commitment to the state it produces,
//! and the server refuses any commitment that does not match what it ended up holding.
//! A client whose view is behind will therefore be refused rather than allowed to write
//! blind — which is the intended behaviour, not an inconvenience to work around.

pub mod engine;
pub mod provision;
pub mod transport;
pub mod wire;

pub use engine::{
    pending_changes, PendingChange, PullOutcome, PushOutcome, SyncAccount, SyncEngine, SyncOutcome,
};
pub use provision::{
    enrol, login, recover, register, replace_credentials, CredentialChange, Credentials, Enrolled,
    Enrolment, Recovery, Registration, RemoteSession,
};
pub use transport::{HttpRequest, HttpResponse, Method, Transport};
pub use wire::{
    HeadDto, ItemDto, KeyEnvelopeResponse, ListVaultsResponse, PreloginResponse, PullResponse,
    PushResponse, SignedHead, VaultDto, B64,
};
