//! Module with testing utilities. None of this is strictly necessary but it
//! makes our lives easier.

use serde::Serialize;

pub fn assert_eq_pretty<T>(actual: T, expected: T)
where
    T: Serialize + std::fmt::Debug + Eq,
{
    // Assert both objects equal with a prettier output string.
    assert_eq!(
        actual,
        expected,
        "Actual:\n{}\nExpected:\n{}",
        serde_json::to_string_pretty(&actual).unwrap(),
        serde_json::to_string_pretty(&expected).unwrap()
    );
}
