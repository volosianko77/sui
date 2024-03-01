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
use sui_types::dynamic_field::DynamicFieldType;
use sui_types::signature::GenericSignature;
use sui_types::signature::{AuthenticatorTrait, VerifyParams};
use sui_types::transaction::TransactionData;
use tracing::info;

pub(crate) struct ZkLoginVerify;

/// Verifies a zkLogin signature based on the provided transaction or personal message.
impl ZkLoginVerify {
    /// Verify a zkLogin signature based on the provided transaction or personal message.
    ///
    /// - `bytes` is either the personal message in raw bytes or transaction data bytes in
    ///    BCS-encoded and then Base64-encoded.
    /// - `signature` is a serialized zkLogin signature that is Base64-encoded.
    /// - `intent_scope` is a u64 representing the intent scope of bytes.
    pub(crate) async fn verify_zklogin_signature(
        db: &Db,
        bytes: String,
        signature: String,
        intent_scope: u64,
        author: SuiAddress,
    ) -> Result<ZkLoginVerifyResult, Error> {
        let epoch = Epoch::query(db, None, None).await?;
        let _chain_id = ChainIdentifier::query(db).await?;

        let name = DynamicFieldName {
            type_: ExactTypeFilter::from_str("u64").unwrap(),
            bcs: Base64::from_str("AQAAAAAAAAA=").unwrap(),
        };
        let df = DynamicField::query(
            db,
            SuiAddress::from_str("0x7").unwrap(),
            None,
            name,
            DynamicFieldType::DynamicField,
            None,
        )
        .await
        .unwrap();

        info!("ttk object {:?}", df.unwrap().super_);

        let Some(curr_epoch) = epoch else {
            return Err(Error::Internal("Cannot get current epoch".to_string()));
        };

        let curr_epoch = curr_epoch.stored.epoch as u64;

        let safe_intent = if intent_scope > u8::MAX as u64 {
            return Err(Error::Internal("Invalid intent scope".to_string()));
        } else {
            IntentScope::try_from(intent_scope as u8)
                .map_err(|_| Error::Internal("Invalid intent scope".to_string()))
        }?;

        let oidc_provider_jwks = ImHashMap::new();
        let verify_params =
            VerifyParams::new(oidc_provider_jwks, vec![], ZkLoginEnv::Prod, true, true);
        match GenericSignature::from_bytes(
            &FastcryptoBase64::decode(&signature)
                .map_err(|_| Error::Internal("Invalid base64 encoding".to_string()))?,
        )
        .map_err(|_| Error::Internal("Cannot parse generic signature".to_string()))?
        {
            GenericSignature::ZkLoginAuthenticator(zk) => {
                let bytes = FastcryptoBase64::decode(&bytes)
                    .map_err(|_| Error::Internal("Invalid bytes".to_string()))?;
                match safe_intent {
                    IntentScope::TransactionData => {
                        let tx_data: TransactionData = bcs::from_bytes(&bytes)
                            .map_err(|_| Error::Internal("Invalid tx data bytes".to_string()))?;
                        let intent_msg =
                            IntentMessage::new(Intent::sui_transaction(), tx_data.clone());
                        let author = tx_data.execution_parts().1;
                        match zk.verify_authenticator(
                            &intent_msg,
                            author,
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
                        let tx_data = PersonalMessage { message: bytes };
                        let intent_msg = IntentMessage::new(
                            Intent {
                                scope: IntentScope::PersonalMessage,
                                version: IntentVersion::V0,
                                app_id: AppId::Sui,
                            },
                            tx_data,
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
                errors: Some(vec!["Unsupported signature scheme".to_string()]),
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
