//! Execution-session helpers shared by SDK and runtime callers: control
//! delivery that bypasses blocked stdin, and consumed-output acknowledgements.

pub mod control;
pub mod output;
