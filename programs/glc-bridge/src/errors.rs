//! Program error taxonomy. Only errors that a currently implemented
//! instruction can raise are defined; the deposit/withdrawal taxonomy
//! (bad proof, claim already processed, bridge paused, …) lands with those
//! instructions in Phases 2–3.

use anchor_lang::prelude::*;

#[error_code]
pub enum BridgeError {
    #[msg("Validator set must contain at least one validator")]
    EmptyValidatorSet,
    #[msg("Validator set exceeds MAX_VALIDATORS")]
    TooManyValidators,
    #[msg("Validator set contains a duplicate key")]
    DuplicateValidator,
    #[msg("Validator key is the all-zero (default) pubkey, which cannot sign")]
    InvalidValidatorKey,
    #[msg("Signature threshold must be at least one")]
    ZeroThreshold,
    #[msg("Signature threshold exceeds the number of validators")]
    ThresholdExceedsValidatorCount,
    #[msg("Signer is not the program upgrade authority")]
    UnauthorizedInitializer,
    #[msg("Signer is not the bridge admin")]
    UnauthorizedAdmin,
    #[msg("Pause state is already set to the requested value")]
    PauseStateUnchanged,
    #[msg("New admin is the same as the current admin")]
    AdminUnchanged,
    #[msg("No admin transfer is pending")]
    NoPendingAdmin,
    #[msg("Signer is not the pending admin")]
    PendingAdminMismatch,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Wrapped mint has already been created")]
    MintAlreadyConfigured,
    #[msg("Wrapped mint has not been created yet")]
    MintNotConfigured,
    #[msg("Mint account does not match the configured wrapped mint")]
    WrongWrappedMint,
    #[msg("Bridge is paused")]
    BridgePaused,
    #[msg("Claim epoch does not match the current validator-set epoch")]
    StaleValidatorEpoch,
    #[msg("Deposit amount must be greater than zero")]
    ZeroDepositAmount,
    #[msg("Deposit amount is below the configured minimum")]
    BelowMinimumDeposit,
    #[msg("Expected an ed25519 signature-verification instruction immediately before this one")]
    MissingSignatureVerification,
    #[msg("Ed25519 verification instruction data is malformed or references other instructions")]
    MalformedSignatureVerification,
    #[msg("A signature covers bytes other than the expected claim message")]
    SignatureMessageMismatch,
    #[msg("A signature was produced by a key that is not a current validator")]
    UnknownValidatorSignature,
    #[msg("The same validator signed more than once")]
    DuplicateValidatorSignature,
    #[msg("Fewer unique validator signatures than the required threshold")]
    InsufficientSignatures,
    #[msg("Withdrawal amount must be greater than zero")]
    ZeroWithdrawalAmount,
    #[msg("Withdrawal amount is below the configured minimum")]
    BelowMinimumWithdrawal,
    #[msg("Goldcoin destination address length is invalid")]
    InvalidGlcAddressLength,

    // ---- Governance (Phase 7a, ADR-0014) ----
    #[msg("Governance timelock must be greater than zero seconds")]
    ZeroGovernanceTimelock,
    #[msg("Pending governance action is not of the expected type")]
    WrongGovernanceAction,
    #[msg("Governance action is still inside its timelock window")]
    GovernanceTimelockNotElapsed,
    #[msg("Pending governance action was approved under a different validator-set epoch")]
    StaleGovernanceProposal,

    // ---- Withdrawal completion (Phase 7f, ADR-0018) ----
    #[msg("Withdrawal is already completed; completion is terminal and irreversible")]
    WithdrawalAlreadyCompleted,
    #[msg("Withdrawal is not in the Pending state and cannot be completed")]
    WithdrawalNotPending,
    #[msg("Withdrawal's reserved payout region is not empty; refusing to overwrite it")]
    PayoutRecordAlreadySet,
    #[msg("Payout txid must not be all zeroes")]
    ZeroPayoutTxid,
    #[msg("Payout block height must be greater than zero")]
    ZeroPayoutHeight,

    // ---- Wrapped-supply cap (Phase 7h-0, ADR-0014 §11) ----
    #[msg("Wrapped-supply cap must be greater than zero")]
    ZeroWrappedSupplyCap,
    #[msg("Mint would take wrapped supply above the configured cap")]
    WrappedSupplyCapExceeded,
    #[msg("A cap change must actually change the cap")]
    WrappedSupplyCapUnchanged,
    #[msg(
        "The admin may only LOWER the wrapped-supply cap; raising it requires threshold-approved, \
         timelocked governance"
    )]
    WrappedSupplyCapNotLowered,
    #[msg("A governance TVL raise must propose a cap above the current one")]
    WrappedSupplyCapNotRaised,

    #[msg("token metadata URI exceeds the maximum length")]
    UriTooLong,
    #[msg("the metadata account is not the PDA Metaplex derives for this mint")]
    InvalidMetadataAccount,
    #[msg("token metadata name must be 1..=32 bytes")]
    NameTooLong,
    #[msg("token metadata symbol must be 1..=10 bytes")]
    SymbolTooLong,
    #[msg("no token metadata exists for this mint yet — create it first")]
    MetadataNotFound,
}
