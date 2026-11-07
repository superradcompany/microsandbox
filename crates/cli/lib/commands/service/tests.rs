use clap::Parser;
use clap::error::ErrorKind;
use microsandbox::{CloudServiceStatus, Operation};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SERVICE_FIXTURE: &str =
    include_str!("../../../../../packages/microsandbox-types/rust/lib/cloud/fixtures/service.json");

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Parser)]
struct TestCli {
    #[command(flatten)]
    args: ServiceArgs,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn parse(args: &[&str]) -> Result<ServiceCommands, clap::Error> {
    TestCli::try_parse_from(std::iter::once("msb").chain(args.iter().copied()))
        .map(|cli| cli.args.command)
}

fn parse_update(args: &[&str]) -> ServiceUpdateArgs {
    match parse(args).unwrap() {
        ServiceCommands::Update(args) => args,
        command => panic!("expected update, got {command:?}"),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn update_needs_a_target_and_actions_parse() {
    let empty = parse(&["update", "my-app"]).unwrap_err();
    assert_eq!(empty.kind(), ErrorKind::MissingRequiredArgument);

    let rotate = parse_update(&["update", "my-app", "--target", "web-2:8080"]);
    assert_eq!(rotate.target.port, 8080);
    assert_eq!(rotate.target.sandbox, "web-2");

    assert!(matches!(
        parse(&["enable", "my-app"]).unwrap(),
        ServiceCommands::Enable(ServiceActionArgs { slug, .. }) if slug == "my-app"
    ));
    assert!(matches!(
        parse(&["disable", "my-app"]).unwrap(),
        ServiceCommands::Disable(ServiceActionArgs { slug, .. }) if slug == "my-app"
    ));

    let old_flag = parse(&["update", "my-app", "--enable"]).unwrap_err();
    assert_eq!(old_flag.kind(), ErrorKind::UnknownArgument);
}

#[test]
fn inspect_and_remove_aliases_parse() {
    assert!(matches!(
        parse(&["inspect", "my-app"]).unwrap(),
        ServiceCommands::Inspect(ServiceInspectArgs { slug, .. }) if slug == "my-app"
    ));
    assert!(matches!(
        parse(&["get", "my-app"]).unwrap(),
        ServiceCommands::Inspect(ServiceInspectArgs { slug, .. }) if slug == "my-app"
    ));
    assert!(matches!(
        parse(&["rm", "my-app"]).unwrap(),
        ServiceCommands::Remove(ServiceRemoveArgs { slug }) if slug == "my-app"
    ));
    assert!(matches!(
        parse(&["remove", "my-app"]).unwrap(),
        ServiceCommands::Remove(ServiceRemoveArgs { slug }) if slug == "my-app"
    ));
    assert_eq!(
        parse(&["delete", "my-app"]).unwrap_err().kind(),
        ErrorKind::InvalidSubcommand
    );
}

#[test]
fn targets_need_a_sandbox_and_a_port_from_1_to_65535() {
    let ServiceCommands::Create(create) =
        parse(&["create", "my-app", "--target", "web-1:8080"]).unwrap()
    else {
        panic!("expected create");
    };
    assert_eq!(create.target.sandbox, "web-1");
    assert_eq!(create.target.port, 8080);

    let missing = parse(&["create", "my-app"]).unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);

    for target in ["web-1:0", "web-1:65536", "web-1:http", "web-1", ":8080"] {
        for command in ["create", "update"] {
            let error = parse(&[command, "my-app", "--target", target]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{target}");
        }
    }
}

#[test]
fn list_parses_the_sandbox_filter() {
    for alias in ["list", "ls"] {
        let ServiceCommands::List(args) =
            parse(&[alias, "--sandbox", "web-2", "--format", "json"]).unwrap()
        else {
            panic!("expected list");
        };

        assert_eq!(args.sandbox.as_deref(), Some("web-2"));
        assert_eq!(args.format, Some(OutputFormat::Json));
    }
}

#[test]
fn service_table_shows_status_and_detached_target() {
    let attached: CloudService = serde_json::from_str(SERVICE_FIXTURE).unwrap();
    let detached = CloudService {
        slug: "old-app".into(),
        status: CloudServiceStatus::Detached,
        target: None,
        ..attached.clone()
    };

    let rendered = service_table(&[attached, detached]).render();

    let rows: Vec<Vec<&str>> = rendered
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(
        rows,
        [
            ["shop", "enabled", "web-1:8080", "https://shop.<domain>"],
            ["old-app", "detached", "-", "https://shop.<domain>"],
        ]
    );
}

#[test]
fn local_backend_refusal_explains_how_to_select_cloud() {
    let refused =
        explain_local_backend(MicrosandboxError::cloud_only(Operation::ServiceGet).into());
    assert_eq!(refused.to_string(), LOCAL_BACKEND_MESSAGE);

    let missing = explain_local_backend(MicrosandboxError::ServiceNotFound("my-app".into()).into());
    assert_eq!(missing.to_string(), "service not found: my-app");
}
