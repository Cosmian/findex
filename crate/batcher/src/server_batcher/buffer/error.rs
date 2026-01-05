use std::fmt::Display;

#[derive(Clone, Debug)]
pub enum Error {
    InvalidResizing { old: usize, new: usize },
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidResizing { old, new } => write!(
                f,
                "cannot resize to a smaller capacity: old ({old}), new ({new})"
            ),
        }
    }
}

impl std::error::Error for Error {}
