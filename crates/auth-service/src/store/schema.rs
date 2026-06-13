//! Table definition for local dev and tests. The production table is owned by
//! CDK (infra/lib/stateful-stack.ts) — keep the two in sync; an infra test
//! asserts the CDK template matches these key/GSI names.

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType, ScalarAttributeType, TimeToLiveSpecification,
};

use super::{StoreError, map_sdk_err};

pub const GSI1: &str = "GSI1";

pub async fn create_table_if_missing(db: &Client, table: &str) -> Result<(), StoreError> {
    let attr = |name: &str| {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(ScalarAttributeType::S)
            .build()
            .map_err(|e| StoreError::Sdk(e.to_string()))
    };
    let key = |name: &str, kt: KeyType| {
        KeySchemaElement::builder()
            .attribute_name(name)
            .key_type(kt)
            .build()
            .map_err(|e| StoreError::Sdk(e.to_string()))
    };

    let result = db
        .create_table()
        .table_name(table)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(attr("PK")?)
        .attribute_definitions(attr("SK")?)
        .attribute_definitions(attr("GSI1PK")?)
        .attribute_definitions(attr("GSI1SK")?)
        .key_schema(key("PK", KeyType::Hash)?)
        .key_schema(key("SK", KeyType::Range)?)
        .global_secondary_indexes(
            GlobalSecondaryIndex::builder()
                .index_name(GSI1)
                .key_schema(key("GSI1PK", KeyType::Hash)?)
                .key_schema(key("GSI1SK", KeyType::Range)?)
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                )
                .build()
                .map_err(|e| StoreError::Sdk(e.to_string()))?,
        )
        .send()
        .await;

    match result {
        Ok(_) => {}
        Err(e)
            if e.as_service_error()
                .is_some_and(|se| se.is_resource_in_use_exception()) =>
        {
            return Ok(()); // already exists
        }
        Err(e) => return Err(map_sdk_err(e)),
    }

    db.update_time_to_live()
        .table_name(table)
        .time_to_live_specification(
            TimeToLiveSpecification::builder()
                .attribute_name("ttl")
                .enabled(true)
                .build()
                .map_err(|e| StoreError::Sdk(e.to_string()))?,
        )
        .send()
        .await
        .map_err(map_sdk_err)?;
    Ok(())
}
