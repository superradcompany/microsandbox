//! Historical catalog field normalization shared by migrations and wire adapters.

use serde_json::{Map, Value, json};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert historical catalog field spellings without dropping unknown fields.
pub fn normalize(value: &mut Value) -> Result<(), &'static str> {
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
            // A legacy null uses the historical default managed root size.
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
    if let Some(secrets) = object
        .get_mut("network")
        .and_then(|network| network.get_mut("secrets"))
        .filter(|secrets| !secrets.is_null())
    {
        super::secrets::normalize(secrets.as_object_mut().ok_or("invalid secrets object")?)?;
    }
    Ok(())
}

fn rename(object: &mut Map<String, Value>, old: &str, new: &str) -> Result<(), &'static str> {
    if let Some(value) = object.remove(old)
        && object.insert(new.to_owned(), value).is_some()
    {
        return Err("conflicting historical and current fields");
    }
    Ok(())
}
