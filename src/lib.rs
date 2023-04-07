pub mod tags;
pub mod digest;
pub mod data_provider;
pub mod digest_provider;

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn tags() {
        assert_eq!(tags::LEAF.value(), 24);
        assert_eq!(tags::LEAF.name().as_ref().unwrap(), Some("leaf").unwrap());
    }
}
