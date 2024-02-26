use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Deref, DerefMut},
};

// This type is needed to add automatic logging (we need all argument types to
// implement `Display`).
#[derive(Eq, PartialEq)]
pub struct Set<Item: Hash + PartialEq + Eq>(HashSet<Item>);

impl<Item: Hash + PartialEq + Eq> Set<Item> {
    pub fn with_capacity(capacity: usize) -> Self {
	Self(HashSet::with_capacity(capacity))
    }
}

impl<Item: Hash + PartialEq + Eq> Default for Set<Item> {
    fn default() -> Self {
        Self(HashSet::new())
    }
}

impl<Item: Hash + PartialEq + Eq> Deref for Set<Item> {
    type Target = HashSet<Item>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Item: Hash + PartialEq + Eq> DerefMut for Set<Item> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Item: Hash + PartialEq + Eq + Display> Display for Set<Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        for tag in &self.0 {
            writeln!(f, "  {},", tag)?;
        }
        writeln!(f, "}}")
    }
}

impl<Item: Hash + PartialEq + Eq + Debug> Debug for Set<Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self.0)
    }
}

impl<Item: Hash + PartialEq + Eq> FromIterator<Item> for Set<Item> {
    fn from_iter<T: IntoIterator<Item = Item>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

impl<Item: Hash + PartialEq + Eq> IntoIterator for Set<Item> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Item: Hash + PartialEq + Eq> From<HashSet<Item>> for Set<Item> {
    fn from(value: HashSet<Item>) -> Self {
        Self(value)
    }
}

impl<Item: Hash + PartialEq + Eq> From<Set<Item>> for HashSet<Item> {
    fn from(value: Set<Item>) -> Self {
        value.0
    }
}

impl<Item: Hash + PartialEq + Eq + Clone> Clone for Set<Item> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(PartialEq)]
pub struct Dx<Tag: Hash + PartialEq + Eq, Item>(HashMap<Tag, Item>);

impl<Tag: Hash + PartialEq + Eq, Item> Default for Dx<Tag, Item> {
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> Deref for Dx<Tag, Item> {
    type Target = HashMap<Tag, Item>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> DerefMut for Dx<Tag, Item> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Tag: Hash + PartialEq + Eq + Display, Item: Display> Display for Dx<Tag, Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Dictionary: {{")?;
        for (tag, value) in self.0.iter() {
            writeln!(f, "'{tag}': {value}")?;
        }
        writeln!(f, "}}")
    }
}

impl<Tag: Hash + PartialEq + Eq + Debug, Item: Debug> Debug for Dx<Tag, Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self.0)
    }
}

impl<Tag: Hash + PartialEq + Eq + Clone, Item: Clone> Clone for Dx<Tag, Item> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> From<HashMap<Tag, Item>> for Dx<Tag, Item> {
    fn from(value: HashMap<Tag, Item>) -> Self {
        Self(value)
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> From<Dx<Tag, Item>> for HashMap<Tag, Item> {
    fn from(value: Dx<Tag, Item>) -> Self {
        value.0
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> FromIterator<(Tag, Item)> for Dx<Tag, Item> {
    fn from_iter<T: IntoIterator<Item = (Tag, Item)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> IntoIterator for Dx<Tag, Item> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub struct Mm<Tag: Hash + PartialEq + Eq, Item>(HashMap<Tag, Vec<Item>>);

impl<Tag: Hash + PartialEq + Eq, Item> Default for Mm<Tag, Item> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> Deref for Mm<Tag, Item> {
    type Target = HashMap<Tag, Vec<Item>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> DerefMut for Mm<Tag, Item> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Tag: Hash + PartialEq + Eq + Clone, Item: Clone> Clone for Mm<Tag, Item> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Tag: Hash + PartialEq + Eq + Display, Item: Display> Display for Mm<Tag, Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Multi-Map: {{")?;
        for (tag, items) in self.iter() {
            writeln!(f, "  '{}': [", tag)?;
            for i in items {
                writeln!(f, "    '{}',", i)?;
            }
            writeln!(f, "  ],")?;
        }
        write!(f, "}}")
    }
}

impl<Tag: Hash + PartialEq + Eq + Debug, Item: Debug> Debug for Mm<Tag, Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mm: {:?}", self.0)
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> From<HashMap<Tag, Vec<Item>>> for Mm<Tag, Item> {
    fn from(value: HashMap<Tag, Vec<Item>>) -> Self {
        Self(value)
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> From<Mm<Tag, Item>> for HashMap<Tag, Vec<Item>> {
    fn from(value: Mm<Tag, Item>) -> Self {
        value.0
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> IntoIterator for Mm<Tag, Item> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> FromIterator<(Tag, Vec<Item>)> for Mm<Tag, Item> {
    fn from_iter<T: IntoIterator<Item = (Tag, Vec<Item>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl<Tag: Hash + PartialEq + Eq, Item: PartialEq> PartialEq for Mm<Tag, Item> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
