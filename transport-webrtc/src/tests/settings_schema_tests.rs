// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::life::Life;

#[test]
fn settings_schema_matches_lifecycle() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    assert_eq!(STATEMENT.settings_schema.len(), SETTINGS_SCHEMA.len());
    let validator = jsonschema::validator_for(&schema).unwrap();
    for (text, accepted) in [
        ("{}", true),
        ("null", false),
        ("[]", false),
        ("true", false),
        ("{\"unknown\":1}", false),
    ] {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(validator.is_valid(&value), accepted, "schema: {text}");
        assert_eq!(
            Framings::validate(text.as_bytes()).is_ok(),
            accepted,
            "lifecycle: {text}"
        );
    }
    assert!(Framings::validate(b"").is_ok());
    assert!(Framings::validate(b" ").is_err());
}
