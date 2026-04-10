use include_dir::{include_dir, Dir};

wit_bindgen::generate!({
    world: "host",
});

const DIST_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/../dist");

struct Host;

impl exports::lattice_id::admin::assets::Guest for Host {
    fn get_asset(path: String) -> Option<exports::lattice_id::admin::assets::Asset> {
        let clean_path = if path.starts_with('/') {
            &path[1..]
        } else {
            &path
        };

        // If path is empty or just /, serve index.html
        let target_path = if clean_path.is_empty() {
            "index.html"
        } else {
            clean_path
        };

        let file = DIST_DIR.get_file(target_path)?;
        let data = file.contents().to_vec();
        
        let content_type = match target_path.split('.').last() {
            Some("html") => "text/html",
            Some("js") => "application/javascript",
            Some("wasm") => "application/wasm",
            Some("css") => "text/css",
            Some("png") => "image/png",
            Some("svg") => "image/svg+xml",
            Some("json") => "application/json",
            _ => "application/octet-stream",
        }.to_string();

        Some(exports::lattice_id::admin::assets::Asset {
            name: target_path.to_string(),
            content_type: content_type,
            data,
        })
    }
}

export!(Host);
