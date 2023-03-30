/// Converts string to vec of strings, splitting on the given delimiter.
/// # Example
///
/// ```
/// use cfd::helpers::split_to_string_vec;
/// let vec = split_to_string_vec(String::from("hello,world"), ",");
/// assert_eq!(vec, vec!["hello", "world"]);
/// ```
///
pub fn split_to_string_vec(string: String, delim: &str) -> Vec<String> {
    string.split(delim).map(|s| s.to_string()).collect()
}

/// Converts string to a binary string.
/// # Example
///
/// ```
/// use cfd::helpers::string_to_binary;
/// let bin_str = string_to_binary("hello");
/// assert_eq!(bin_str, "0110100001100101011011000110110001101111");
/// ```
///
pub fn string_to_binary(s: &str) -> String {
    s.chars()
        .map(|c| format!("{:08b}", c as u8))
        .collect::<Vec<String>>()
        .join("")
}

/// Converts bool to string value.
/// # Example
///
/// ```
/// use cfd::helpers::bool_to_str;
/// let bool_str = bool_to_str(true);
/// assert_eq!(bool_str, "true");
/// ```
///
pub fn bool_to_str<'a>(b: bool) -> &'a str {
    if b {
        "true"
    } else {
        "false"
    }
}
