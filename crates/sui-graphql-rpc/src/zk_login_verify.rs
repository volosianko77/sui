// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::types::sui_address::SuiAddress;
use async_graphql::*;
use fastcrypto::encoding::Encoding;
use fastcrypto::{encoding::Base64, traits::ToFromBytes};
use shared_crypto::intent::{
    AppId, Intent, IntentMessage, IntentScope, IntentVersion, PersonalMessage,
};
use sui_sdk::SuiClient;
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
        ctx: &Context<'_>,
        bytes: String,
        signature: String,
        intent_scope: u64,
        author: SuiAddress,
    ) -> Result<ZkLoginVerifyResult> {
        let sui_sdk_client: &Option<SuiClient> = ctx
            .data()
            .map_err(|_| Error::Internal("Unable to fetch Sui SDK client".to_string()))
            .extend()?;
        let sui_sdk_client = sui_sdk_client
            .as_ref()
            .ok_or_else(|| Error::Internal("Sui SDK client not initialized".to_string()))
            .extend()?;

        let curr_epoch = sui_sdk_client
            .governance_api()
            .get_latest_sui_system_state()
            .await?
            .epoch;
        let safe_intent = if intent_scope > u8::MAX as u64 {
            return Err(Error::Internal("Invalid intent scope".to_string()).into());
        } else {
            IntentScope::try_from(intent_scope as u8)
                .map_err(|_| Error::Internal("Invalid intent scope".to_string()))
        }?;
        let verify_params = VerifyParams::default();
        info!(
            "jzjz bytes: {}, signature: {}, intent_scope: {}, author: {}",
            bytes, signature, intent_scope, author
        );
        match GenericSignature::from_bytes(
            &Base64::decode(&signature)
                .map_err(|_| Error::Internal("Invalid base64 encoding".to_string()))?,
        )
        .map_err(|_| Error::Internal("Cannot parse generic signature".to_string()))?
        {
            GenericSignature::ZkLoginAuthenticator(zk) => {
                let bytes = Base64::decode(&bytes)
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
