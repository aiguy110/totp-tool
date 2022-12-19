use std::{fmt::Display, error::Error};

#[derive(Debug)]
pub struct GenericError {
    description: String
}

impl GenericError {
    pub fn new(description: &str) -> Self {
        GenericError { description: description.to_owned() }
    }
}

impl Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.description)
    }
}

impl Error for GenericError {
    fn description(&self) -> &str {
        &self.description
    }
}