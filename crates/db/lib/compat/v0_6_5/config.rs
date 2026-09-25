//! Previous image, resource and mount spellings accepted by v0.6.5.

use serde_json::{Map, Value, json};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert previous catalog field spellings without dropping unknown fields.
pub fn to_current(value: &mut Value) -> Result<(), &'static str> {
    let object = value.as_object_mut().ok_or("expected an object")?;
    if let Some(image) = object.get_mut("image").and_then(Value::as_object_mut) {
        for (old, new) in [
            ("oci", "Oci"),
            ("bind", "Bind"),
            ("disk_image", "DiskImage"),
        ] {
            rename(image, old, new)?;
        }
        if let Some(bind) = image.get_mut("Bind")
            && let Some(path) = bind.as_str()
        {
            *bind = json!({"path": path, "follow_root_symlinks": false});
        }
        if let Some(oci) = image.get_mut("Oci").and_then(Value::as_object_mut)
            && let Some(size) = oci.remove("upper_size_mib")
        {
            // A legacy null uses the previous default managed root size.
            // Preserve explicit sizes; never replace a requested disk kind.
            if oci.contains_key("root_disk") {
                return Err("conflicting root-disk representations");
            }
            if !size.is_null() {
                oci.insert(
                    "root_disk".into(),
                    json!({"kind":"managed", "size_mib":size}),
                );
            }
        }
    }
    if let Some(resources) = object.get_mut("resources").and_then(Value::as_object_mut) {
        rename(resources, "vcpus", "cpus")?;
        rename(resources, "max_vcpus", "max_cpus")?;
    }
    if let Some(mounts) = object.get_mut("mounts").and_then(Value::as_array_mut) {
        for mount in mounts {
            let Some(old) = mount.as_object_mut() else {
                continue;
            };
            if old.contains_key("type") {
                continue;
            }
            let variants = [
                ("bind", "Bind"),
                ("named", "Named"),
                ("tmpfs", "Tmpfs"),
                ("disk_image", "DiskImage"),
            ];
            if let Some((key, tag)) = variants.into_iter().find(|(key, _)| old.contains_key(*key)) {
                if old.len() != 1 {
                    return Err("ambiguous mount representation");
                }
                let mut fields = old
                    .remove(key)
                    .and_then(|value| value.as_object().cloned())
                    .ok_or("invalid mount fields")?;
                if fields.insert("type".into(), json!(tag)).is_some() {
                    return Err("conflicting mount tag");
                }
                *mount = Value::Object(fields);
            }
        }
    }
    if let Some(policy) = object.get_mut("pull_policy") {
        match policy.as_str() {
            Some("if_missing") => *policy = json!("IfMissing"),
            Some("always") => *policy = json!("Always"),
            Some("never") => *policy = json!("Never"),
            _ => {}
        }
    }
    Ok(())
}

/// Restore the CPU and mount representation read by v0.6.5.
/// Keep image tags unchanged: older schema migrations still inspect `Oci`
/// and `Bind` when reversing root-disk and bind options, and v0.6.5 accepts them.
pub fn to_previous_version(value: &mut Value) -> Result<(), &'static str> {
    let original = value.clone();
    let object = value.as_object_mut().ok_or("expected an object")?;
    if let Some(resources) = object.get_mut("resources").and_then(Value::as_object_mut) {
        rename(resources, "cpus", "vcpus")?;
        rename(resources, "max_cpus", "max_vcpus")?;
    }
    if let Some(mounts) = object.get_mut("mounts").and_then(Value::as_array_mut) {
        for mount in mounts {
            let fields = mount.as_object_mut().ok_or("invalid mount fields")?;
            let Some(tag) = fields.remove("type") else {
                continue;
            };
            let key = match tag.as_str() {
                Some("Bind") => "bind",
                Some("Named") => "named",
                Some("Tmpfs") => "tmpfs",
                Some("DiskImage") => "disk_image",
                _ => return Err("mount type is not supported by v0.6.5"),
            };
            *mount = json!({key: std::mem::take(fields)});
        }
    }
    let mut restored = value.clone();
    let mut expected = original;
    to_current(&mut restored)?;
    to_current(&mut expected)?;
    if restored != expected {
        return Err("configuration cannot be preserved in v0.6.5");
    }
    Ok(())
}

fn rename(object: &mut Map<String, Value>, old: &str, new: &str) -> Result<(), &'static str> {
    if let Some(value) = object.remove(old)
        && object.insert(new.to_owned(), value).is_some()
    {
        return Err("conflicting previous and current fields");
    }
    Ok(())
}
