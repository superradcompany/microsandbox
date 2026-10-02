//! Cloud violation policies introduced in v0.6.7.

use serde::Deserialize;

use crate::cloud::{CloudHostPattern, CloudViolationAction};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ViolationAction {
    Block,
    BlockAndLog,
    BlockAndTerminate,
    Passthrough { hosts: Vec<CloudHostPattern> },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ViolationAction {
    pub(crate) fn into_current(
        self,
    ) -> (Option<CloudViolationAction>, Option<Vec<CloudHostPattern>>) {
        match self {
            Self::Block => (Some(CloudViolationAction::Block), None),
            Self::BlockAndLog => (Some(CloudViolationAction::BlockAndLog), None),
            Self::BlockAndTerminate => (Some(CloudViolationAction::BlockAndTerminate), None),
            Self::Passthrough { hosts } => (None, Some(hosts)),
        }
    }
}
