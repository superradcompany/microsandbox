# microsandbox-supervisor-client

Typed Rust client for the local microsandbox supervisor protocol.

The client writes the `MSBS` selector, negotiates generation 1 with CBOR hello/welcome records, and then reuses the shared framed client for unary operations and watch streams. Construct `SupervisorClientConfig` with the SDK process identity and digest of the canonical microsandbox home; no process is started implicitly by this package.

```rust,no_run
use microsandbox_supervisor_client::{GetSupervisorStatus, SupervisorClient, SupervisorClientConfig};

# async fn example(config: SupervisorClientConfig) -> Result<(), Box<dyn std::error::Error>> {
let client = SupervisorClient::connect("/run/user/1000/microsandbox/supervisor.sock", config).await?;
let status = client.request_typed(&GetSupervisorStatus).await?;
println!("catalog revision: {}", status.catalog_revision);
# Ok(())
# }
```
