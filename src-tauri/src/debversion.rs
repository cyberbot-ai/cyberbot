use std::cmp::Ordering;
fn parts(v: &str) -> Option<(&str, &str, &str)> {
    if v.is_empty()
        || v.len() > 256
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+:~_-".contains(&b))
    {
        return None;
    }
    let (epoch, rest) = v.split_once(':').unwrap_or(("0", v));
    if epoch.is_empty()
        || !epoch.bytes().all(|b| b.is_ascii_digit())
        || !rest.as_bytes().first()?.is_ascii_digit()
    {
        return None;
    }
    let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, "0"));
    if upstream.is_empty() || revision.is_empty() {
        return None;
    }
    Some((epoch.trim_start_matches('0'), upstream, revision))
}
fn order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) => c as i32 + 256,
    }
}
fn segment(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while a.get(i).is_some_and(|c| !c.is_ascii_digit())
            || b.get(j).is_some_and(|c| !c.is_ascii_digit())
        {
            let cmp = order(a.get(i).copied()).cmp(&order(b.get(j).copied()));
            if cmp != Ordering::Equal {
                return cmp;
            }
            if i < a.len() {
                i += 1;
            }
            if j < b.len() {
                j += 1;
            }
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let (ai, bj) = (i, j);
        while a.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        while b.get(j).is_some_and(u8::is_ascii_digit) {
            j += 1;
        }
        let cmp = (i - ai)
            .cmp(&(j - bj))
            .then_with(|| a[ai..i].cmp(&b[bj..j]));
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    Ordering::Equal
}
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    let (ae, au, ar) = parts(a)?;
    let (be, bu, br) = parts(b)?;
    Some(
        ae.len()
            .cmp(&be.len())
            .then_with(|| ae.cmp(be))
            .then_with(|| segment(au, bu))
            .then_with(|| segment(ar, br)),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distro_ordering() {
        for (a, b) in [
            ("1.0~rc1", "1.0"),
            ("1.0-1", "1.0-1+deb12u1"),
            ("1.0-1~bpo12+1", "1.0-1"),
            ("1:9", "2:1"),
            ("1.09", "1.10"),
            ("1a", "1+"),
        ] {
            assert_eq!(compare(a, b), Some(Ordering::Less));
            assert_eq!(compare(b, a), Some(Ordering::Greater));
        }
        assert_eq!(compare("0:1.01", "1.1-0"), Some(Ordering::Equal));
        assert_eq!(compare("v1", "1"), None);
    }
}
