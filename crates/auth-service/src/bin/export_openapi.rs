//! Prints the OpenAPI document to stdout. CI diffs `openapi/openapi.json`
//! against this output to catch drift (`pnpm generate` regenerates both the
//! committed spec and the SDK's TypeScript types).

use auth_service::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", ApiDoc::openapi().to_pretty_json()?);
    Ok(())
}
