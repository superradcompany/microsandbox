use std::collections::BTreeMap;

use microsandbox_types_macros::ConfigPatch;

#[derive(Debug, Clone, Default, PartialEq, ConfigPatch)]
struct Inner {
    scalar: u8,
    nullable: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, ConfigPatch)]
struct Outer {
    #[config_patch(nested)]
    inner: Inner,
    values: Vec<u8>,
    optional: Option<u32>,
    future_field: bool,
}

#[derive(Debug, Clone, Default, PartialEq, ConfigPatch)]
struct OptionalOuter {
    #[config_patch(nested)]
    inner: Option<Inner>,
}

#[derive(Debug, Clone, Default, PartialEq, ConfigPatch)]
#[config_patch(name = RenamedPatch)]
struct Renamed {
    value: u8,
}

#[derive(Debug, Clone, Default, PartialEq, ConfigPatch)]
struct Collections {
    #[config_patch(merge)]
    values: Vec<u8>,
    #[config_patch(merge)]
    optional_values: Option<Vec<u8>>,
    #[config_patch(merge)]
    labels: BTreeMap<String, String>,
    #[config_patch(merge_with = merge_unique)]
    unique_values: Vec<u8>,
}

fn merge_unique(base: &mut Vec<u8>, higher: Vec<u8>) {
    for value in higher {
        if !base.contains(&value) {
            base.push(value);
        }
    }
}

#[test]
fn generated_patch_preserves_presence_and_recurses() {
    let mut target = Outer {
        inner: Inner {
            scalar: 1,
            nullable: Some("inherited".into()),
        },
        values: vec![1, 2],
        optional: Some(7),
        future_field: false,
    };
    let source = Outer {
        inner: Inner {
            scalar: 3,
            nullable: None,
        },
        values: vec![9],
        optional: None,
        future_field: true,
    };

    OuterPatch::from_present_fields(source).apply_to(&mut target);

    assert_eq!(target.inner.scalar, 3);
    assert_eq!(target.inner.nullable.as_deref(), Some("inherited"));
    assert_eq!(target.values, vec![9]);
    assert_eq!(target.optional, Some(7));
    assert!(target.future_field);
}

#[test]
fn clear_removes_nullable_changes_from_the_patch() {
    let mut target = Outer {
        inner: Inner {
            scalar: 3,
            nullable: Some("inherited".into()),
        },
        optional: Some(7),
        ..Default::default()
    };

    OuterPatch::new()
        .inner(
            InnerPatch::new()
                .scalar(9)
                .clear_scalar()
                .nullable("higher".into())
                .clear_nullable(),
        )
        .optional(9)
        .clear_optional()
        .future_field(true)
        .clear_future_field()
        .apply_to(&mut target);

    assert_eq!(target.inner.scalar, 3);
    assert_eq!(target.inner.nullable.as_deref(), Some("inherited"));
    assert_eq!(target.optional, Some(7));
    assert!(!target.future_field);
}

#[test]
fn optional_nested_patches_modify_and_clear_pending_changes() {
    let mut target = OptionalOuter {
        inner: Some(Inner {
            scalar: 1,
            nullable: Some("inherited".into()),
        }),
    };

    OptionalOuterPatch::new()
        .modify_inner(|inner| inner.scalar(2))
        .apply_to(&mut target);
    assert_eq!(
        target.inner,
        Some(Inner {
            scalar: 2,
            nullable: Some("inherited".into()),
        })
    );

    OptionalOuterPatch::new()
        .modify_inner(|inner| inner.scalar(9))
        .clear_inner()
        .apply_to(&mut target);
    assert_eq!(target.inner.as_ref().unwrap().scalar, 2);

    target.inner = Some(Inner {
        scalar: 7,
        nullable: Some("must survive".into()),
    });
    OptionalOuterPatch::new()
        .clear_inner()
        .overlay(OptionalOuterPatch::new().modify_inner(|inner| inner.scalar(4)))
        .apply_to(&mut target);
    assert_eq!(
        target.inner,
        Some(Inner {
            scalar: 4,
            nullable: Some("must survive".into()),
        })
    );

    OptionalOuterPatch::from_present_fields(OptionalOuter::default()).apply_to(&mut target);
    assert!(target.inner.is_some());
}

#[test]
fn generated_patch_name_can_be_overridden() {
    let mut target = Renamed::default();
    RenamedPatch::new().value(7).apply_to(&mut target);
    assert_eq!(target.value, 7);
}

#[test]
fn collection_fields_merge_replace_and_clear() {
    let mut target = Collections {
        values: vec![1],
        optional_values: Some(vec![1]),
        labels: BTreeMap::from([("shared".into(), "lower".into())]),
        unique_values: vec![1],
    };

    CollectionsPatch::new()
        .values(vec![2])
        .values(vec![3])
        .optional_values(vec![2])
        .labels(BTreeMap::from([
            ("shared".into(), "higher".into()),
            ("new".into(), "value".into()),
        ]))
        .unique_values(vec![1, 2])
        .apply_to(&mut target);

    assert_eq!(target.values, [1, 2, 3]);
    assert_eq!(target.optional_values.as_deref(), Some([1, 2].as_slice()));
    assert_eq!(target.labels["shared"], "higher");
    assert_eq!(target.labels["new"], "value");
    assert_eq!(target.unique_values, [1, 2]);

    CollectionsPatch::new()
        .replace_values(vec![9])
        .optional_values(vec![9])
        .clear_optional_values()
        .labels(BTreeMap::from([("ignored".into(), "value".into())]))
        .clear_labels()
        .apply_to(&mut target);

    assert_eq!(target.values, [9]);
    assert_eq!(target.optional_values.as_deref(), Some([1, 2].as_slice()));
    assert_eq!(target.labels["shared"], "higher");
    assert_eq!(target.labels["new"], "value");
}

#[test]
fn collection_patch_overlay_preserves_replace_and_merge_order() {
    let mut target = Collections {
        values: vec![0],
        ..Default::default()
    };

    CollectionsPatch::new()
        .replace_values(vec![1])
        .overlay(CollectionsPatch::new().values(vec![2]))
        .apply_to(&mut target);
    assert_eq!(target.values, [1, 2]);

    CollectionsPatch::new()
        .values(vec![3])
        .overlay(CollectionsPatch::new().replace_values(vec![4]))
        .apply_to(&mut target);
    assert_eq!(target.values, [4]);
}
