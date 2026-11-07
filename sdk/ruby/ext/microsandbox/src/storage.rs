//! Shared inspection/recovery bridges; Ruby wrappers supply explicit scope and options.

use magnus::{Error, RModule, Ruby, function};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn diagnose(ruby: &Ruby, config: String, selection: String) -> Result<String, Error> {
    super::run(ruby, async move {
        microsandbox_core::setup::binding_diagnose_storage(&config, &selection).await
    })
}

fn recover(ruby: &Ruby, name: String, options: String) -> Result<String, Error> {
    super::run(ruby, async move {
        let options = serde_json::from_str(&options)?;
        let result = microsandbox_core::Sandbox::recover_storage(&name, options).await?;
        Ok(serde_json::to_string(&result)?)
    })
}

pub(super) fn register(module: RModule) -> Result<(), Error> {
    module.define_module_function("_diagnose_storage_json", function!(diagnose, 2))?;
    module.define_module_function("_recover_storage_json", function!(recover, 2))?;
    Ok(())
}
