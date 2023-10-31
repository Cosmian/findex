use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    ops::{Deref, DerefMut},
    vec::IntoIter,
};

use base64::engine::{general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{
    reexport::rand_core::CryptoRngCore, Aes256Gcm, DemInPlace, FixedSizeCBytes, Instantiable,
    Nonce, RandomFixedSizeCBytes, SymmetricKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::CoreError,
    parameters::{MAC_LENGTH, NONCE_LENGTH, SYM_KEY_LENGTH},
    TOKEN_LENGTH,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token([u8; TOKEN_LENGTH]);

impl Token {
    pub const LENGTH: usize = TOKEN_LENGTH;
}

impl Deref for Token {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Token> for [u8; TOKEN_LENGTH] {
    fn from(value: Token) -> Self {
        value.0
    }
}

impl From<[u8; TOKEN_LENGTH]> for Token {
    fn from(bytes: [u8; TOKEN_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for Token {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; TOKEN_LENGTH]>::try_from(value)
            .map_err(|_| {
                CoreError::Conversion(format!(
                    "cannot create token from {} bytes, {TOKEN_LENGTH} expected",
                    value.len(),
                ))
            })
            .map(Into::into)
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", STANDARD.encode(&**self))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tokens(pub HashSet<Token>);

impl Deref for Tokens {
    type Target = HashSet<Token>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();
        for token in &self.0 {
            output.push_str(&format!("\n{token}"));
        }
        write!(f, "{output}")
    }
}

impl FromIterator<Token> for Tokens {
    fn from_iter<T: IntoIterator<Item = Token>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

impl IntoIterator for Tokens {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = Token;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<HashSet<Token>> for Tokens {
    fn from(value: HashSet<Token>) -> Self {
        Self(value)
    }
}

impl From<Tokens> for HashSet<Token> {
    fn from(value: Tokens) -> Self {
        value.0
    }
}

/// Seed used to derive a key.
#[derive(Debug)]
pub struct Seed<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> Seed<LENGTH> {
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let mut seed = [0; LENGTH];
        rng.fill_bytes(&mut seed);
        Self(seed)
    }
}

impl<const LENGTH: usize> Default for Seed<LENGTH> {
    fn default() -> Self {
        Self([0; LENGTH])
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for Seed<LENGTH> {
    fn from(value: [u8; LENGTH]) -> Self {
        Self(value)
    }
}

impl<const LENGTH: usize> AsRef<[u8]> for Seed<LENGTH> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const LENGTH: usize> AsMut<[u8]> for Seed<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const LENGTH: usize> Zeroize for Seed<LENGTH> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const LENGTH: usize> Drop for Seed<LENGTH> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for Seed<LENGTH> {}

/// Key used by the Dictionary Encryption Scheme.
///
/// It is composed of two sub-keys:
/// - the token sub-key is used to generate secure tokens from tags;
/// - the value sub-key is used to encrypt the values stored.
pub struct EdxKey {
    pub token: SymmetricKey<{ SYM_KEY_LENGTH }>,
    pub value: SymmetricKey<{ SYM_KEY_LENGTH }>,
}

impl ZeroizeOnDrop for EdxKey {}

/// Value stored inside the EDX. It is composed of:
/// - a AESGCM-256 ciphertext;
/// - a nonce;
/// - a MAC tag.
///
/// TODO: the nonce used to encrypt the values should be derived from the token
/// to avoid storing yet another random value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedValue<const VALUE_LENGTH: usize> {
    pub ciphertext: [u8; VALUE_LENGTH],
    pub tag: [u8; MAC_LENGTH],
    pub nonce: Nonce<NONCE_LENGTH>,
}

impl<const VALUE_LENGTH: usize> From<&EncryptedValue<VALUE_LENGTH>> for Vec<u8> {
    fn from(value: &EncryptedValue<VALUE_LENGTH>) -> Self {
        let mut res = Self::with_capacity(EncryptedValue::<VALUE_LENGTH>::LENGTH);
        res.extend(&value.nonce.0);
        res.extend(&value.ciphertext);
        res.extend(&value.tag);
        res
    }
}

impl<const VALUE_LENGTH: usize> TryFrom<&[u8]> for EncryptedValue<VALUE_LENGTH> {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::LENGTH {
            return Err(Self::Error::Conversion(format!(
                "incorrect length for encrypted value: {} bytes give, {} bytes expected",
                value.len(),
                Self::LENGTH
            )));
        }

        let nonce = Nonce::try_from_slice(&value[..NONCE_LENGTH])?;
        let ciphertext =
            <[u8; VALUE_LENGTH]>::try_from(&value[NONCE_LENGTH..NONCE_LENGTH + VALUE_LENGTH])
                .map_err(|e| Self::Error::Conversion(e.to_string()))?;
        let tag = <[u8; MAC_LENGTH]>::try_from(&value[NONCE_LENGTH + VALUE_LENGTH..])
            .map_err(|e| Self::Error::Conversion(e.to_string()))?;
        Ok(Self {
            ciphertext,
            tag,
            nonce,
        })
    }
}

impl<const VALUE_LENGTH: usize> EncryptedValue<VALUE_LENGTH> {
    pub const LENGTH: usize = MAC_LENGTH + NONCE_LENGTH + VALUE_LENGTH;

    /// Encrypts the value using the given key.
    pub fn encrypt(
        rng: &mut impl CryptoRngCore,
        key: &SymmetricKey<SYM_KEY_LENGTH>,
        value: [u8; VALUE_LENGTH],
    ) -> Result<Self, CoreError> {
        let mut res = Self {
            ciphertext: value,
            nonce: Nonce::from([0; NONCE_LENGTH]),
            tag: [0; MAC_LENGTH],
        };
        rng.fill_bytes(&mut res.nonce.0);
        let aead = Aes256Gcm::new(key);
        let tag = aead
            .encrypt_in_place_detached(&res.nonce, &mut res.ciphertext, None)
            .map_err(CoreError::CryptoCore)?;
        res.tag.copy_from_slice(tag.as_slice());
        Ok(res)
    }

    /// Decrypts the value using the given key.
    pub fn decrypt(
        &self,
        key: &SymmetricKey<SYM_KEY_LENGTH>,
    ) -> Result<[u8; VALUE_LENGTH], CoreError> {
        let mut res = self.ciphertext;
        let aead = Aes256Gcm::new(key);
        aead.decrypt_in_place_detached(&self.nonce, &mut res, &self.tag, None)
            .map_err(CoreError::CryptoCore)?;
        Ok(res)
    }
}

impl<const LENGTH: usize> Display for EncryptedValue<LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ciphertext {}", STANDARD.encode(self.ciphertext))?;
        write!(f, "tag {}", STANDARD.encode(self.tag))?;
        write!(f, "nonce {}", STANDARD.encode(self.nonce.as_bytes()))
    }
}

#[derive(Debug, Default)]
pub struct TokenWithEncryptedValueList<const VALUE_LENGTH: usize>(
    pub Vec<(Token, EncryptedValue<VALUE_LENGTH>)>,
);

impl<const VALUE_LENGTH: usize> Deref for TokenWithEncryptedValueList<VALUE_LENGTH> {
    type Target = [(Token, EncryptedValue<VALUE_LENGTH>)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const VALUE_LENGTH: usize> Display for TokenWithEncryptedValueList<VALUE_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token with EncryptedValue list:")?;
        for (token, encrypted_value) in self.iter() {
            write!(f, "\n({token}, {encrypted_value})")?;
        }
        Ok(())
    }
}

impl<const VALUE_LENGTH: usize> From<Vec<(Token, EncryptedValue<VALUE_LENGTH>)>>
    for TokenWithEncryptedValueList<VALUE_LENGTH>
{
    fn from(value: Vec<(Token, EncryptedValue<VALUE_LENGTH>)>) -> Self {
        Self(value)
    }
}

impl<const VALUE_LENGTH: usize> From<TokenWithEncryptedValueList<VALUE_LENGTH>>
    for Vec<(Token, EncryptedValue<VALUE_LENGTH>)>
{
    fn from(value: TokenWithEncryptedValueList<VALUE_LENGTH>) -> Self {
        value.0
    }
}

impl<const VALUE_LENGTH: usize> FromIterator<(Token, EncryptedValue<VALUE_LENGTH>)>
    for TokenWithEncryptedValueList<VALUE_LENGTH>
{
    fn from_iter<T: IntoIterator<Item = (Token, EncryptedValue<VALUE_LENGTH>)>>(iter: T) -> Self {
        Self(Vec::from_iter(iter))
    }
}

impl<const VALUE_LENGTH: usize> IntoIterator for TokenWithEncryptedValueList<VALUE_LENGTH> {
    type IntoIter = IntoIter<(Token, EncryptedValue<VALUE_LENGTH>)>;
    type Item = (Token, EncryptedValue<VALUE_LENGTH>);

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Default, Debug, Clone)]
pub struct TokenToEncryptedValueMap<const VALUE_LENGTH: usize>(
    pub HashMap<Token, EncryptedValue<VALUE_LENGTH>>,
);

impl<const VALUE_LENGTH: usize> Deref for TokenToEncryptedValueMap<VALUE_LENGTH> {
    type Target = HashMap<Token, EncryptedValue<VALUE_LENGTH>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const VALUE_LENGTH: usize> DerefMut for TokenToEncryptedValueMap<VALUE_LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const VALUE_LENGTH: usize> Display for TokenToEncryptedValueMap<VALUE_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token to EncryptedValue map:")?;
        for (token, encrypted_value) in self.iter() {
            write!(f, "\n{token} -> {encrypted_value}")?;
        }
        Ok(())
    }
}

impl<const VALUE_LENGTH: usize> From<HashMap<Token, EncryptedValue<VALUE_LENGTH>>>
    for TokenToEncryptedValueMap<VALUE_LENGTH>
{
    fn from(value: HashMap<Token, EncryptedValue<VALUE_LENGTH>>) -> Self {
        Self(value)
    }
}

impl<const VALUE_LENGTH: usize> From<TokenToEncryptedValueMap<VALUE_LENGTH>>
    for HashMap<Token, EncryptedValue<VALUE_LENGTH>>
{
    fn from(value: TokenToEncryptedValueMap<VALUE_LENGTH>) -> Self {
        value.0
    }
}

impl<const VALUE_LENGTH: usize> FromIterator<(Token, EncryptedValue<VALUE_LENGTH>)>
    for TokenToEncryptedValueMap<VALUE_LENGTH>
{
    fn from_iter<T: IntoIterator<Item = (Token, EncryptedValue<VALUE_LENGTH>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl<const VALUE_LENGTH: usize> IntoIterator for TokenToEncryptedValueMap<VALUE_LENGTH> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
