//! F-19: arbitrary HTML through the snapshot planner and sanitizer: no panic; local names stay
//! inside `_files/`; re-parsing the output finds a CSP meta and no script, frame, plugin or base
//! element and no `on*` attribute.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use std::cell::RefCell;
use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use lol_html::{RewriteStrSettings, element, rewrite_str};
use url::Url;
use webfilter::snapshot;

fuzz_target!(|data: &[u8]| {
    let html = String::from_utf8_lossy(data);
    let base = Url::parse("https://site.example/dir/page.html").unwrap();
    let planned = snapshot::plan(&html, &base, false);
    assert!(planned.iter().all(|u| matches!(u.scheme(), "http" | "https")));
    let map: HashMap<String, String> = planned
        .iter()
        .take(snapshot::MAX_ASSETS)
        .map(|u| (u.to_string(), snapshot::local_name("page", u, "image/png")))
        .collect();
    for local in map.values() {
        assert!(local.starts_with("page_files/") && !local.contains("..") && !local.contains('\\'));
    }
    let out = snapshot::rewrite(&html, &base, &map, false);
    let bad: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let csp = RefCell::new(false);
    let _ = rewrite_str(
        &out,
        RewriteStrSettings::new()
            .append_element_content_handler(element!("script, iframe, frame, object, embed, base", |el| {
                bad.borrow_mut().push(el.tag_name());
                Ok(())
            }))
            .append_element_content_handler(element!("meta[http-equiv]", |el| {
                *csp.borrow_mut() |= el.get_attribute("http-equiv").is_some_and(|v| v.eq_ignore_ascii_case("content-security-policy"));
                Ok(())
            }))
            .append_element_content_handler(element!("*", |el| {
                for a in el.attributes() {
                    if a.name().starts_with("on") {
                        bad.borrow_mut().push(a.name());
                    }
                }
                Ok(())
            })),
    );
    assert!(*csp.borrow(), "no CSP meta");
    assert!(bad.borrow().is_empty(), "{:?} survived", bad.borrow());
});
