//! Prints the OpenAPI document to stdout. CI checks `openapi/openapi.json`
//! for drift against this output. (Populated incrementally as handlers gain
//! utoipa annotations.)

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let doc = utoipa::openapi::OpenApiBuilder::new()
        .info(
            utoipa::openapi::InfoBuilder::new()
                .title("auth.ericminassian.com")
                .version(env!("CARGO_PKG_VERSION"))
                .build(),
        )
        .build();
    println!("{}", doc.to_pretty_json()?);
    Ok(())
}
