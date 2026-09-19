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

#[derive(Debug, Clone, Default, PartialEq, ConfigPatch)]
struct NullableCollection {
    #[config_patch(nullable)]
    values: Option<Vec<u8>>,
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

    let mut patch = OptionalOuterPatch::new();
    patch.inner.get_or_insert_default().scalar = Some(2);
    patch.apply_to(&mut target);
    assert_eq!(
        target.inner,
        Some(Inner {
            scalar: 2,
            nullable: Some("inherited".into()),
        })
    );

    let mut patch = OptionalOuterPatch::new();
    patch.inner.get_or_insert_default().scalar = Some(9);
    patch.inner = None;
    patch.apply_to(&mut target);
    assert_eq!(target.inner.as_ref().unwrap().scalar, 2);

    target.inner = Some(Inner {
        scalar: 7,
        nullable: Some("must survive".into()),
    });
    OptionalOuterPatch::new()
        .clear_inner()
        .overlay(OptionalOuterPatch::new().inner(InnerPatch::new().scalar(4)))
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

#[derive(Debug, Clone, PartialEq, ConfigPatch)]
struct Defaults {
    #[config_patch(nested)]
    inner: Inner,
    #[config_patch(nullable)]
    workdir: Option<String>,
    #[config_patch(merge)]
    values: Vec<u8>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            inner: Inner {
                scalar: 7,
                nullable: Some("inherited".into()),
            },
            workdir: Some("/default".into()),
            values: vec![1],
        }
    }
}

#[test]
fn into_config_preserves_target_defaults_for_absent_fields() {
    assert_eq!(DefaultsPatch::new().into_config(), Defaults::default());

    let config = DefaultsPatch::new()
        .inner(InnerPatch::new().scalar(9))
        .values(vec![2])
        .into_config();
    assert_eq!(config.inner.scalar, 9);
    assert_eq!(config.inner.nullable.as_deref(), Some("inherited"));
    assert_eq!(config.workdir.as_deref(), Some("/default"));
    assert_eq!(config.values, [1, 2]);
}

#[test]
fn into_config_applies_clears_and_collection_replacement_after_overlays() {
    let config = DefaultsPatch::new()
        .workdir("/lower".into())
        .values(vec![2])
        .overlay(
            DefaultsPatch::new()
                .set_workdir(None)
                .replace_values(vec![3]),
        )
        .overlay(DefaultsPatch::new().values(vec![4]))
        .into_config();
    assert_eq!(config.workdir, None);
    assert_eq!(config.values, [3, 4]);
    assert_eq!(config.inner, Defaults::default().inner);
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

#[test]
fn mutable_methods_preserve_nested_and_clear_semantics() {
    let mut patch = OuterPatch::new();
    patch
        .inner_mut(InnerPatch::new().scalar(3))
        .values_mut(vec![2])
        .optional_mut(9)
        .clear_optional_mut()
        .overlay_mut(OuterPatch::new().values(vec![4]).future_field(true));
    patch.inner.nullable = Some("new".into());
    let mut target = Outer {
        optional: Some(7),
        ..Default::default()
    };
    patch.apply_to(&mut target);
    assert_eq!(target.inner.scalar, 3);
    assert_eq!(target.inner.nullable.as_deref(), Some("new"));
    assert_eq!(target.values, vec![4]);
    assert_eq!(target.optional, Some(7));
    assert!(target.future_field);

    let mut optional = OptionalOuterPatch::new();
    optional
        .inner_mut(InnerPatch::new().scalar(8))
        .clear_inner_mut();
    optional.inner.get_or_insert_default().nullable = Some("nested".into());
    let mut target = OptionalOuter::default();
    optional.apply_to(&mut target);
    assert_eq!(
        target.inner.unwrap(),
        Inner {
            scalar: 0,
            nullable: Some("nested".into())
        }
    );
}

#[test]
fn mutable_collection_methods_keep_replacement_and_merge_order() {
    let mut patch = CollectionsPatch::new();
    patch
        .values_mut(vec![1])
        .replace_values_mut(vec![2])
        .values_mut(vec![3])
        .optional_values_mut(vec![1])
        .replace_optional_values_mut(vec![4])
        .optional_values_mut(vec![5])
        .labels_mut(BTreeMap::from([("discarded".into(), "value".into())]))
        .clear_labels_mut()
        .unique_values_mut(vec![1, 2])
        .unique_values_mut(vec![2, 3])
        .overlay_mut(CollectionsPatch::new().values(vec![4]));
    let mut target = Collections {
        values: vec![0],
        optional_values: Some(vec![0]),
        labels: BTreeMap::from([("inherited".into(), "value".into())]),
        unique_values: vec![0, 1],
    };
    patch.apply_to(&mut target);
    assert_eq!(target.values, vec![2, 3, 4]);
    assert_eq!(target.optional_values, Some(vec![4, 5]));
    assert_eq!(
        target.labels,
        BTreeMap::from([("inherited".into(), "value".into())])
    );
    assert_eq!(target.unique_values, vec![0, 1, 2, 3]);
}

#[test]
fn direct_collection_updates_and_accessors_reuse_allocations() {
    let mut values = Vec::with_capacity(8);
    values.push(1);
    let allocation = values.as_ptr();
    let mut patch = OuterPatch::new().values(values);
    patch.values.get_or_insert_default().push(2);
    assert_eq!(patch.values.as_ref().unwrap().as_ptr(), allocation);
    assert_eq!(patch.values.as_deref(), Some([1, 2].as_slice()));

    let mut merge_patch = CollectionsPatch::new().replace_values(patch.values.take().unwrap());
    merge_patch.get_values_mut().push(3);
    assert_eq!(merge_patch.get_values().unwrap().as_ptr(), allocation);
    assert_eq!(merge_patch.get_values().unwrap(), &[1, 2, 3]);
}

#[test]
fn collection_accessors_preserve_merge_and_replacement_modes() {
    let mut target = Collections {
        values: vec![0],
        optional_values: Some(vec![0]),
        labels: BTreeMap::from([("inherited".into(), "value".into())]),
        unique_values: vec![0, 1],
    };
    let mut patch = CollectionsPatch::new();
    patch.get_values_mut().push(1);
    patch.get_optional_values_mut().push(1);
    patch
        .get_labels_mut()
        .insert("added".into(), "value".into());
    patch.get_unique_values_mut().extend([1, 2, 2]);
    patch.apply_to(&mut target);
    assert_eq!(target.values, [0, 1]);
    assert_eq!(target.optional_values, Some(vec![0, 1]));
    assert_eq!(target.labels.len(), 2);
    assert_eq!(target.unique_values, [0, 1, 2]);

    let mut patch = CollectionsPatch::new()
        .replace_values(vec![2])
        .replace_optional_values(vec![2])
        .replace_labels(BTreeMap::new());
    patch.get_values_mut().push(3);
    patch.get_optional_values_mut().push(3);
    patch.get_labels_mut().insert("only".into(), "value".into());
    patch.overlay_mut(CollectionsPatch::new().values(vec![4]));
    patch.apply_to(&mut target);
    assert_eq!(target.values, [2, 3, 4]);
    assert_eq!(target.optional_values, Some(vec![2, 3]));
    assert_eq!(
        target.labels,
        BTreeMap::from([("only".into(), "value".into())])
    );

    let mut patch = CollectionsPatch::new()
        .replace_values(vec![9])
        .clear_values();
    patch.get_values_mut().push(5);
    patch.apply_to(&mut target);
    assert_eq!(target.values, [2, 3, 4, 5]);
}

#[test]
fn direct_nullable_fields_distinguish_omitted_cleared_and_empty_values() {
    let mut target = NullableCollection {
        values: Some(vec![1]),
    };
    let mut patch = NullableCollectionPatch::new();
    patch.values = None;
    patch.apply_to(&mut target);
    assert_eq!(target.values, Some(vec![1]));

    let mut patch = NullableCollectionPatch::new();
    patch.values = Some(None);
    patch.apply_to(&mut target);
    assert_eq!(target.values, None);

    let mut patch = NullableCollectionPatch::new();
    patch.values = Some(Some(Vec::new()));
    patch.apply_to(&mut target);
    assert_eq!(target.values, Some(Vec::new()));
}

mod visibility {
    use microsandbox_types_macros::ConfigPatch;

    #[derive(Debug, Clone, Default, ConfigPatch)]
    pub struct Config {
        pub scalar: u8,
        pub(crate) values: Vec<u8>,
        #[config_patch(nested)]
        pub(super) nested: Nested,
        #[config_patch(merge)]
        pub merged: Vec<u8>,
        #[config_patch(merge)]
        pub(crate) restricted_merged: Vec<u8>,
        #[config_patch(nullable)]
        pub(super) optional: Option<u8>,
        private: bool,
    }

    #[derive(Debug, Clone, Default, ConfigPatch)]
    pub struct Nested {
        pub scalar: u8,
    }
}

#[test]
fn public_and_restricted_fields_are_accessible_across_modules() {
    let mut patch = visibility::ConfigPatch::new();
    patch.scalar = Some(2);
    patch.values.get_or_insert_default().push(3);
    patch.nested.scalar = Some(4);
    patch.get_merged_mut().push(5);
    let mut target = visibility::Config::default();
    patch.apply_to(&mut target);
    assert_eq!(target.scalar, 2);
    assert_eq!(target.values, [3]);
    assert_eq!(target.nested.scalar, 4);
    assert_eq!(target.merged, [5]);
}

#[test]
fn field_methods_follow_source_visibility_across_modules() {
    let mut patch = visibility::ConfigPatch::new()
        .scalar(2)
        .values(vec![3])
        .nested(visibility::NestedPatch::new().scalar(4))
        .replace_merged(vec![5])
        .restricted_merged(vec![6])
        .set_optional(Some(7));
    patch.scalar_mut(8);
    patch.values_mut(vec![9]);
    patch.nested_mut(visibility::NestedPatch::new().scalar(10));
    patch.merged_mut(vec![11]);
    patch.replace_restricted_merged_mut(vec![12]);
    patch.get_restricted_merged_mut().push(13);
    assert_eq!(patch.get_merged().unwrap(), &[5, 11]);
    assert_eq!(patch.get_restricted_merged().unwrap(), &[12, 13]);
    patch.set_optional_mut(None);
    patch.clear_values_mut();
    let config = patch.clear_nested().into_config();
    assert_eq!(config.scalar, 8);
    assert!(config.values.is_empty());
    assert_eq!(config.nested.scalar, 0);
    assert_eq!(config.merged, [5, 11]);
    assert_eq!(config.restricted_merged, [12, 13]);
    assert_eq!(config.optional, None);
}

#[derive(Debug, Clone, Default, ConfigPatch)]
struct NestedMap {
    #[config_patch(nested, merge)]
    entries: BTreeMap<String, Inner>,
}

#[test]
fn nested_maps_overlay_entry_fields_and_can_replace_the_map() {
    let mut target = NestedMap {
        entries: BTreeMap::from([
            (
                "same".into(),
                Inner {
                    scalar: 1,
                    nullable: Some("keep".into()),
                },
            ),
            ("other".into(), Inner::default()),
        ]),
    };
    let base = NestedMapPatch::new().entries(BTreeMap::from([(
        "same".into(),
        InnerPatch::new().scalar(2),
    )]));
    let higher = NestedMapPatch::new().entries(BTreeMap::from([(
        "same".into(),
        InnerPatch::new().scalar(3),
    )]));
    base.overlay(higher).apply_to(&mut target);
    assert_eq!(target.entries["same"].scalar, 3);
    assert_eq!(target.entries["same"].nullable.as_deref(), Some("keep"));
    assert!(target.entries.contains_key("other"));
    let replacement = NestedMapPatch::new().replace_entries(BTreeMap::from([(
        "same".into(),
        InnerPatch::new().scalar(4),
    )]));
    replacement.apply_to(&mut target);
    assert_eq!(target.entries.len(), 1);
    assert_eq!(target.entries["same"].nullable, None);
    let converted = NestedMapPatch::from_present_fields(target.clone());
    let mut restored = NestedMap::default();
    converted.apply_to(&mut restored);
    assert_eq!(restored.entries, target.entries);
}
