// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::data::Db;
use crate::error::Error;
use crate::types::base64::Base64;
use crate::types::chain_identifier::ChainIdentifier;
use crate::types::dynamic_field::{DynamicField, DynamicFieldName};
use crate::types::epoch::Epoch;
use crate::types::sui_address::SuiAddress;
use crate::types::type_filter::ExactTypeFilter;
use async_graphql::*;
use fastcrypto::encoding::Encoding;
use fastcrypto::{encoding::Base64 as FastcryptoBase64, traits::ToFromBytes};
use fastcrypto_zkp::bn254::zk_login_api::ZkLoginEnv;
use im::hashmap::HashMap as ImHashMap;
use shared_crypto::intent::{
    AppId, Intent, IntentMessage, IntentScope, IntentVersion, PersonalMessage,
};
use std::str::FromStr;
use sui_types::authenticator_state::{ActiveJwk, AuthenticatorStateInner};
use sui_types::digests::{get_mainnet_chain_identifier, get_testnet_chain_identifier};
use sui_types::dynamic_field::{DynamicFieldType, Field};
use sui_types::signature::GenericSignature;
use sui_types::signature::{AuthenticatorTrait, VerifyParams};
use sui_types::transaction::TransactionData;
use tracing::warn;

pub(crate) struct ZkLoginVerify;

/// Verifies a zkLogin signature based on the provided transaction or personal message.
impl ZkLoginVerify {
    /// Verify a zkLogin signature based on the provided transaction or personal message
    /// based on current epoch, chain id, and latest JWKs fetched on-chain.
    ///
    /// If the signature is valid, the function returns a `ZkLoginVerifyResult` with no
    /// errors. If the signature is invalid, the function returns a `ZkLoginVerifyResult`
    /// with a list of errors.
    ///
    /// - `bytes` is either the personal message in raw bytes or transaction data bytes in
    ///    BCS-encoded and then Base64-encoded.
    /// - `signature` is a serialized zkLogin signature that is Base64-encoded.
    /// - `intent_scope` is a u64 representing the intent scope of bytes.
    /// - `author` is the address of the signer of the transaction or personal msg.
    pub(crate) async fn verify_zklogin_signature(
        db: &Db,
        bytes: String,
        signature: String,
        intent_scope: u64,
        author: SuiAddress,
    ) -> Result<ZkLoginVerifyResult, Error> {
        // parse intent scope from u64.
        let safe_intent = if intent_scope > u8::MAX as u64 {
            return Err(Error::Client("Invalid intent scope".to_string()));
        } else {
            IntentScope::try_from(intent_scope as u8)
                .map_err(|_| Error::Client("Unsupported intent scope".to_string()))
        }?;

        // get current epoch from db.
        let Some(curr_epoch) = Epoch::query(db, None, None).await? else {
            return Err(Error::Internal(
                "Cannot get current epoch from db".to_string(),
            ));
        };
        let curr_epoch = curr_epoch.stored.epoch as u64;

        // get chain id from db and determine zklogin_env.
        let chain_id = ChainIdentifier::query(db).await?;
        let zklogin_env = match chain_id == get_mainnet_chain_identifier()
            || chain_id == get_testnet_chain_identifier()
        {
            true => ZkLoginEnv::Prod,
            _ => ZkLoginEnv::Test,
        };

        // fetch on-chain JWKs from dynamic field of system object.
        let df = DynamicField::query(
            db,
            SuiAddress::from_str("0x7")
                .map_err(|_| Error::Internal("Invalid system object".to_string()))?,
            None,
            DynamicFieldName {
                type_: ExactTypeFilter::from_str("u64")
                    .map_err(|_| Error::Internal("Invalid df name type".to_string()))?,
                bcs: Base64::from_str("AQAAAAAAAAA=")
                    .map_err(|_| Error::Internal("Invalid df name bcs".to_string()))?,
            },
            DynamicFieldType::DynamicField,
            None,
        )
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        let binding = df.ok_or(Error::Internal("Cannot find df".to_string()))?;

        let move_object = binding
            .super_
            .super_
            .native_impl()
            .ok_or(Error::Internal("Cannot pase object from df".to_string()))?
            .data
            .try_as_move()
            .ok_or_else(|| Error::Internal("df not a Move object".to_string()))?;

        let inner = bcs::from_bytes::<Field<u64, AuthenticatorStateInner>>(move_object.contents())
            .map_err(|err| {
                Error::Client(format!("Invalid bcs for AuthenticatorStateInner {}", err))
            })?
            .value;

        // construct verify params with active jwks and zklogin_env.
        let mut oidc_provider_jwks = ImHashMap::new();
        for active_jwk in &inner.active_jwks {
            let ActiveJwk { jwk_id, jwk, .. } = active_jwk;
            match oidc_provider_jwks.entry(jwk_id.clone()) {
                im::hashmap::Entry::Occupied(_) => {
                    warn!("JWK with kid {:?} already exists", jwk_id);
                }
                im::hashmap::Entry::Vacant(entry) => {
                    warn!("inserting JWK with kid: {:?}", jwk_id);
                    entry.insert(jwk.clone());
                }
            }
        }
        let verify_params = VerifyParams::new(oidc_provider_jwks, vec![], zklogin_env, true, true);

        match GenericSignature::from_bytes(
            &FastcryptoBase64::decode(&signature)
                .map_err(|_| Error::Client("Invalid base64 for signature".to_string()))?,
        )
        .map_err(|_| Error::Client("Cannot parse generic signature".to_string()))?
        {
            GenericSignature::ZkLoginAuthenticator(zk) => {
                let bytes = FastcryptoBase64::decode(&bytes)
                    .map_err(|_| Error::Client("Invalid base64 for bytes".to_string()))?;
                match safe_intent {
                    IntentScope::TransactionData => {
                        let tx_data: TransactionData = bcs::from_bytes(&bytes)
                            .map_err(|_| Error::Client("Invalid tx data bytes".to_string()))?;
                        let intent_msg =
                            IntentMessage::new(Intent::sui_transaction(), tx_data.clone());
                        let tx_sender = tx_data.execution_parts().1;
                        if tx_sender != author.into() {
                            return Err(Error::Client("Tx sender mismatch author".to_string()));
                        }
                        match zk.verify_authenticator(
                            &intent_msg,
                            tx_sender,
                            Some(curr_epoch),
                            &verify_params,
                        ) {
                            Ok(_) => Ok(ZkLoginVerifyResult { errors: None }),
                            Err(e) => Ok(ZkLoginVerifyResult {
                                errors: Some(vec![e.to_string()]),
                            }),
                        }
                    }
                    IntentScope::PersonalMessage => {
                        let data = PersonalMessage { message: bytes };
                        let intent_msg = IntentMessage::new(
                            Intent {
                                scope: IntentScope::PersonalMessage,
                                version: IntentVersion::V0,
                                app_id: AppId::Sui,
                            },
                            data,
                        );

                        match zk.verify_authenticator(
                            &intent_msg,
                            author.into(),
                            Some(curr_epoch),
                            &verify_params,
                        ) {
                            Ok(_) => Ok(ZkLoginVerifyResult { errors: None }),
                            Err(e) => Ok(ZkLoginVerifyResult {
                                errors: Some(vec![e.to_string()]),
                            }),
                        }
                    }
                    _ => Ok(ZkLoginVerifyResult {
                        errors: Some(vec!["Invalid intent scope".to_string()]),
                    }),
                }
            }
            _ => Ok(ZkLoginVerifyResult {
                errors: Some(vec!["Endpoint only supports zkLogin signature".to_string()]),
            }),
        }
    }
}

/// The result of the zkLogin signature verification.
#[derive(SimpleObject, Clone)]
pub(crate) struct ZkLoginVerifyResult {
    /// The errors field captures any verification error
    pub errors: Option<Vec<String>>,
}
