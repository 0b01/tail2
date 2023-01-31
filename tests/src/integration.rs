use assert_cmd::Command;
use predicates::prelude::predicate;

#[test]
fn test_malloc() {
    let mut cmd = Command::cargo_bin("tail2-tests").unwrap();

    cmd.arg("malloc");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("SentStackCount = 2"))
        .stdout(predicate::str::contains("unwind_success: Some"));
}
