// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::data::Db;
use crate::error::Error;
use crate::types::base64::Base64;
use crate::types::chain_identifier::ChainIdentifier;
use crate::types::dynamic_field::{DynamicField, DynamicFieldName};
use crate::types::epoch::Epoch;
use crate::types::object::Object;
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
use sui_types::authenticator_state::{AuthenticatorState, AuthenticatorStateInner};
use sui_types::object::MoveObject;
use std::str::FromStr;
use sui_types::dynamic_field::{get_dynamic_field_from_store, DynamicFieldType};
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
        let object = Object::query(db, SuiAddress::from_str("0x7").unwrap(), crate::types::object::ObjectLookupKey::Latest).await?.unwrap();
        let move_object = MoveObject::try_from(&object).map_err(|_| {
            Error::Internal(format!(
                "Expected {} to be CoinMetadata, but it is not an object.",
                object.address,
            ))
        })?;
        let outer = bcs::from_bytes::<AuthenticatorState>(move_object.contents())
            .map_err(|err| Error::Internal(err.to_string()))?;
    
        let id = outer.id.id.bytes;
        let inner: AuthenticatorStateInner =
            get_dynamic_field_from_store(object_store, id, &outer.version).map_err(|err| {
                Error::Internal(format!(
                    "Failed to load sui system state inner object with ID {:?} and version {:?}: {:?}",
                    id, outer.version, err
                ))
            })?;
        info!("tktkinner {:?}", inner);
        // let df = DynamicField::query(
        //     db,
        //     SuiAddress::from_str("0x7").unwrap(),
        //     None,
        //     DynamicFieldName {
        //         type_: ExactTypeFilter::from_str("u64").unwrap(),
        //         bcs: Base64::from_str("AQAAAAAAAAA=").unwrap(),
        //     },
        //     DynamicFieldType::DynamicField,
        //     None,
        // )
        // .await
        // .unwrap();

        // let move_object = df.unwrap().super_.super_.try_as_move().ok_or_else(|| {
        //     Error::CursorNoFirstLast
        // })?;

        //  match df.unwrap().super_.super_.kind {
        //     crate::types::object::ObjectKind::Historical(x, stored) => {
        //         info!("1tk object {:?}", x);
        //         let move_object = x.data.try_as_move().ok_or_else(|| {
        //                  Error::Client("not a move object".to_string())
        //          })?;
        //          info!("2tk move_object {:?}", move_object);

        //          let outer = bcs::from_bytes::<AuthenticatorStateInner>(move_object.contents())
        //          .map_err(|e| Error::Internal(e.to_string()))?;
        //         info!("3tk {:?}", outer);   
        //     }
        //     _ => {}
        // }
        // let field: Field<AuthenticatorStateInner> = df.unwrap().super_
        // .native
        // .to_rust()
        // .ok_or_else(|| Error::Internal("Malformed Suins NameRecord".to_string()))?;

        // match df.unwrap().super_.super_.kind {
        //     crate::types::object::ObjectKind::Historical(x, stored) => {
        //         info!("ttk object {:?}", x);
        //         match &x.data {
        //            sui_types::object::Data::Move(ev) => {
        //             ev.to_rust()
        //                 info!("ttk kfk {:?}", ev.contents());
        //                 let v: AuthenticatorStateInner = bcs::from_bytes(ev.contents()).unwrap();
        //                 info!("ttk v {:?}", v);
        //             }
        //             _ => {}
        //         }

        //     }
        //     _ => {}
        // }
        // info!("ttk object {:?}", df.unwrap().super_.super_.kind);
        // info!("ttk type {:?}", df.unwrap().super_.native.type_());
        // let v: AuthenticatorStateInner = bcs::from_bytes(df.unwrap().super_.native.contents()).unwrap();
        // info!("ttk v {:?}", v);

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
