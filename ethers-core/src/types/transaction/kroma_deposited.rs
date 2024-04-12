use super::rlp_opt;
use crate::types::{Address, Bytes, NameOrAddress, Signature, Transaction, H256, U256};
use rlp::{Decodable, RlpStream};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const NUM_TX_FIELDS: usize = 7;

/// An error involving a transaction request.
#[derive(Debug, Error)]
pub enum KromaDepositedRequestError {
    /// When decoding a transaction request from RLP
    #[error(transparent)]
    DecodingError(#[from] rlp::DecoderError),
}

/// Parameters for sending a transaction
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct KromaDepositedTransactionRequest {
    /// The source hash which uniquely identifies the origin of the deposit
    #[serde(rename = "sourceHash")]
    pub source_hash: Option<H256>,

    /// Sender address or ENS name
    pub from: Option<Address>,

    /// Recipient address (None for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<NameOrAddress>,

    /// The ETH value to mint on L2, locked on L1 (None for no mint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mint: Option<U256>,

    /// Transferred value (None for no transfer)
    pub value: Option<U256>,

    /// Supplied gas (None for sensible default)
    pub gas: Option<U256>,

    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see Ethereum Contract ABI
    pub data: Option<Bytes>,
}

impl KromaDepositedTransactionRequest {
    /// Creates an empty transaction request with all fields left empty
    pub fn new() -> Self {
        Self::default()
    }

    // Builder pattern helpers

    /// Sets the `source hash` field in the transaction to the provided value
    #[must_use]
    pub fn source_hash<T: Into<H256>>(mut self, source_hash: T) -> Self {
        self.source_hash = Some(source_hash.into());
        self
    }

    /// Sets the `from` field in the transaction to the provided value
    #[must_use]
    pub fn from<T: Into<Address>>(mut self, from: T) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets the `to` field in the transaction to the provided value
    #[must_use]
    pub fn to<T: Into<NameOrAddress>>(mut self, to: T) -> Self {
        self.to = Some(to.into());
        self
    }

    /// Sets the `mint` field in the transaction to the provided value
    #[must_use]
    pub fn mint<T: Into<U256>>(mut self, mint: T) -> Self {
        self.mint = Some(mint.into());
        self
    }

    /// Sets the `value` field in the transaction to the provided value
    #[must_use]
    pub fn value<T: Into<U256>>(mut self, value: T) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Sets the `gas` field in the transaction to the provided value
    #[must_use]
    pub fn gas<T: Into<U256>>(mut self, gas: T) -> Self {
        self.gas = Some(gas.into());
        self
    }

    /// Sets the `data` field in the transaction to the provided value
    #[must_use]
    pub fn data<T: Into<Bytes>>(mut self, data: T) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Produces the RLP encoding of the transaction.
    pub fn rlp(&self) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_list(NUM_TX_FIELDS);
        rlp_opt(&mut rlp, &self.source_hash);
        rlp_opt(&mut rlp, &self.from);
        rlp_opt(&mut rlp, &self.to);
        rlp_opt(&mut rlp, &self.mint);
        rlp_opt(&mut rlp, &self.value);
        rlp_opt(&mut rlp, &self.gas);
        rlp_opt(&mut rlp, &self.data.as_deref());
        rlp.out().freeze().into()
    }

    /// Produces the RLP encoding of the transaction.
    ///
    /// # Note
    /// In general, self.rlp_signed() may produce RLP encoding with provided signature.
    /// however, in case of Deposit Transaction, it returns a result which equals to self.rlp(),
    /// since Deposit Transaction does not have signature to encode.
    pub fn rlp_signed(&self) -> Bytes {
        self.rlp()
    }

    /// Decodes fields based on the RLP offset passed.
    fn decode_base_rlp(rlp: &rlp::Rlp, offset: &mut usize) -> Result<Self, rlp::DecoderError> {
        let mut offset = 0;
        let mut txn = KromaDepositedTransactionRequest::new();

        txn.source_hash = Some(rlp.at(offset)?.as_val()?);
        offset += 1;
        txn.from = Some(rlp.at(offset)?.as_val()?);
        offset += 1;
        txn.to = Some(rlp.at(offset)?.as_val()?);
        offset += 1;
        txn.mint = Some(rlp.at(offset)?.as_val()?);
        offset += 1;
        txn.value = Some(rlp.at(offset)?.as_val()?);
        offset += 1;
        txn.gas = Some(rlp.at(offset)?.as_val()?);
        offset += 1;

        // finally we need to extract the data which will be encoded as another rlp
        let data = rlp::Rlp::new(rlp.at(offset)?.as_raw()).data()?;
        txn.data = Some(Bytes::from(data.to_vec()));
        Ok(txn)
    }

    /// Decodes the given RLP into a transaction
    /// Note: this transaction does not have a signature
    pub(crate) fn decode_signed_rlp(rlp: &rlp::Rlp) -> Result<(Self, Signature), rlp::DecoderError> {
        let mut offset = 0;
        let txn = Self::decode_base_rlp(rlp, &mut offset)?;
        let sig = Signature { r: 0.into(), s: 0.into(), v: 0 };

        Ok((txn, sig))
    }
}

/// Get a KromaDepositedTransactionRequest from a rlp encoded byte stream
impl Decodable for KromaDepositedTransactionRequest {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Self::decode_base_rlp(rlp, &mut 0)
    }
}

impl From<&Transaction> for KromaDepositedTransactionRequest {
    fn from(tx: &Transaction) -> KromaDepositedTransactionRequest {
        if tx.transaction_type.unwrap().as_u64() != 0x7e {
            panic!("does not match transaction type");
        }

        KromaDepositedTransactionRequest {
            source_hash: tx.source_hash,
            from: Some(tx.from),
            to: tx.to.map(NameOrAddress::Address),
            mint: tx.mint,
            gas: Some(tx.gas),
            value: Some(tx.value),
            data: Some(Bytes(tx.input.0.clone())),
        }
    }
}

#[cfg(feature = "kroma")]
#[cfg(all(not(feature = "celo"), not(feature = "optimism")))]
#[cfg(test)]
mod tests {
    use super::KromaDepositedTransactionRequest;
    use crate::{
        types::{Bytes, Transaction},
        utils::keccak256,
    };
    use rlp::{Decodable, Rlp};
    use std::str::FromStr;

    /// Deposit Transaction built by hand.
    fn fixture_deposit_request_tx() -> KromaDepositedTransactionRequest {
        serde_json::from_str(
            r#"{
                "from": "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001",
                "gas": "0xf4240",
                "gasPrice": "0x0",
                "hash": "0x88fadf7173bfde177e03873165c4e77f60f5293a5a130294937ea47d1618f426",
                "data": "0xefc674eb00000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000064c31d8f00000000000000000000000000000000000000000000000000000000120535f8ef16bfe6d35d4216950df5634cb24cde7b3a183b16108d63e66d25a75f42eeaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f424000000000000000000000000000000000000000000000000000000000000007d0",
                "nonce": "0x13",
                "to": "0x4200000000000000000000000000000000000002",
                "value": "0x0",
                "type": "0x7e",
                "sourceHash": "0x03978998c47aeb48300ca2d447c39b66705f5442cf7f7b255f6fbbed8a7ff985",
                "mint": "0x0"
            }"#,
        )
            .unwrap()
    }

    /// Deposit Transaction from Kroma RPC node.
    fn fixture_deposit_tx() -> Transaction {
        serde_json::from_str(
            r#"{
                "blockHash": "0x85a7660992e79203e3896ac8d80352bdc05fcbb29ea99be481b6fd33d1b7147c",
                "blockNumber": "0x13",
                "from": "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001",
                "gas": "0xf4240",
                "gasPrice": "0x0",
                "hash": "0x88fadf7173bfde177e03873165c4e77f60f5293a5a130294937ea47d1618f426",
                "input": "0xefc674eb00000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000064c31d8f00000000000000000000000000000000000000000000000000000000120535f8ef16bfe6d35d4216950df5634cb24cde7b3a183b16108d63e66d25a75f42eeaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f424000000000000000000000000000000000000000000000000000000000000007d0",
                "nonce": "0x13",
                "to": "0x4200000000000000000000000000000000000002",
                "transactionIndex": "0x0",
                "value": "0x0",
                "type": "0x7e",
                "v": "0x0",
                "r": "0x0",
                "s": "0x0",
                "sourceHash": "0x03978998c47aeb48300ca2d447c39b66705f5442cf7f7b255f6fbbed8a7ff985",
                "mint": "0x0"
            }"#
        ).unwrap()
    }

    /// Expected rlp bytes.
    fn fixture_rlp_bytes() -> Bytes {
        Bytes::from_str("0xf90178a003978998c47aeb48300ca2d447c39b66705f5442cf7f7b255f6fbbed8a7ff98594deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000028080830f4240b90124efc674eb00000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000064c31d8f00000000000000000000000000000000000000000000000000000000120535f8ef16bfe6d35d4216950df5634cb24cde7b3a183b16108d63e66d25a75f42eeaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f424000000000000000000000000000000000000000000000000000000000000007d0").unwrap()
    }

    #[test]
    fn init_from_raw_string() {
        let tx = fixture_deposit_request_tx();
        let src_hash = hex::encode(tx.source_hash.unwrap());
        let caller = hex::encode(tx.from.unwrap());
        let callee = hex::encode(tx.to.unwrap().as_address().unwrap());
        let mint = tx.mint.unwrap().to_string();
        let value = tx.value.unwrap().to_string();
        let data = hex::encode(tx.data.unwrap());
        assert_eq!(src_hash, "03978998c47aeb48300ca2d447c39b66705f5442cf7f7b255f6fbbed8a7ff985");
        assert_eq!(caller, "deaddeaddeaddeaddeaddeaddeaddeaddead0001");
        assert_eq!(callee, "4200000000000000000000000000000000000002");
        assert_eq!(mint, "0");
        assert_eq!(value, "0");
        assert_eq!(data, "efc674eb00000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000064c31d8f00000000000000000000000000000000000000000000000000000000120535f8ef16bfe6d35d4216950df5634cb24cde7b3a183b16108d63e66d25a75f42eeaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f424000000000000000000000000000000000000000000000000000000000000007d0");
    }

    #[test]
    fn init_by_rlp_bytes() {
        let rlp_bytes = fixture_rlp_bytes();
        let got_rlp = Rlp::new(rlp_bytes.as_ref());

        let deposit_request = KromaDepositedTransactionRequest::decode(&got_rlp).unwrap();
        assert_eq!(rlp_bytes, deposit_request.rlp());
    }

    #[test]
    fn init_from_response_transaction() {
        let expected_tx = fixture_deposit_request_tx();
        let tx = fixture_deposit_tx();

        let deposit_request: KromaDepositedTransactionRequest = (&tx).into();
        assert_eq!(expected_tx.rlp(), deposit_request.rlp())
    }

    #[test]
    fn rlp_hash() {
        let tx = fixture_deposit_request_tx();
        let rlp_bytes = tx.rlp();
        assert_eq!(rlp_bytes, fixture_rlp_bytes());

        let mut rlp_for_tx_hash = vec![];
        rlp_for_tx_hash.extend_from_slice(&[0x7E]);
        rlp_for_tx_hash.extend_from_slice(rlp_bytes.as_ref());

        // calculate tx hash
        let tx_hash = keccak256(Bytes::from(rlp_for_tx_hash));
        let tx_hash_hex = hex::encode(tx_hash);
        assert_eq!(tx_hash_hex, "88fadf7173bfde177e03873165c4e77f60f5293a5a130294937ea47d1618f426");
    }

    #[test]
    fn encode_rlp_kroma_deposit_tx() {
        let tx = fixture_deposit_tx();

        assert_eq!(tx.hash(), tx.hash);

        let rlp_bytes = tx.rlp().to_vec();
        let decoded_tx = Transaction::decode(&rlp::Rlp::new(&rlp_bytes)).unwrap();

        assert_eq!(tx.source_hash, decoded_tx.source_hash);
        assert_eq!(tx.from, decoded_tx.from);
        assert_eq!(tx.to, decoded_tx.to);
        assert_eq!(tx.mint, decoded_tx.mint);
        assert_eq!(tx.value, decoded_tx.value);
        assert_eq!(tx.gas, decoded_tx.gas);
        assert_eq!(tx.input, decoded_tx.input);

    }
}
