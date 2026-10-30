//! PT-1.3: 10k regexes + 64 KB adversarial inputs; each evaluation < 5 ms, nothing rejected
//! silently. Release-mode stress test, run by `just pentest-p1` (`--ignored`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::time::{Duration, Instant};

use webfilter::blocklist::parse_patterns;

#[test]
#[ignore = "release-mode stress test; run via just pentest-p1"]
fn pt_1_3_ten_thousand_patterns_linear_time() {
    let shapes = ["(a+)+$", "(a|aa)+b", "(.*a){8}z", "([a-z]+)*=", "(x+x+)+y", "^(a?){20}a{20}$"];
    let text: String =
        (0..10_000).map(|i| format!("[id=p{i}] {}{i}\n", shapes[i % shapes.len()])).collect();
    let start = Instant::now();
    let parsed = parse_patterns(&text).unwrap();
    println!("compiled {} patterns in {:?}", parsed.entries, start.elapsed());
    assert_eq!(parsed.invalid, 0, "no pattern rejected silently");
    assert_eq!(parsed.entries, 10_000);

    let inputs = [
        format!("{}!", "a".repeat(64 * 1024)),
        "x".repeat(64 * 1024),
        "ab=".repeat(64 * 1024 / 3),
        (0..64 * 1024).map(|i| if i % 2 == 0 { 'a' } else { '/' }).collect::<String>(),
    ];
    let mut worst = Duration::ZERO;
    for input in &inputs {
        let views = [input.clone(), input.clone(), input.clone()];
        let _ = parsed.list.matches(&views); // warm the lazy DFA
        let t = Instant::now();
        let _ = parsed.list.matches(&views);
        worst = worst.max(t.elapsed());
    }
    println!("worst evaluation (3 views x 64 KB): {worst:?}");
    assert!(worst < Duration::from_millis(5), "evaluation took {worst:?}");
}
