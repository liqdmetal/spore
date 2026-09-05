//! Mycelium Solana mailbox program.
//!
//! Durable per-recipient inbox. Each recipient has a PDA account
//! `pda = PDA(program_id, [b"mycelium", recipient_pubkey])` that stores a list
//! of mycelium E2E-encrypted envelopes. The program NEVER sees plaintext and
//! NEVER holds a key — the envelope is opaque bytes produced by the client's
//! internal/secure layer (eph_pub || nonce || ciphertext).
//!
//! Instructions:
//!   - deliver(to, data): append `data` to `to`'s inbox PDA. Anyone may deliver
//!     (sender signs; recipient does not — email semantics). Payer = sender.
//!   - burn(to, index): empty one message (compost semantics).
//!
//! Only the recipient may read/burn their own inbox (the `to` signer must match
//! the PDA owner). Delivery is open to anyone, like sending email to an address.
#![deny(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

/// One stored message: sender + opaque envelope + sequence.
#[derive(BorshSerialize, BorshDeserialize, Default, Clone)]
pub struct StoredMessage {
    /// Sender pubkey bytes.
    pub from: [u8; 32],
    /// Opaque mycelium E2E envelope (kind || eph_pub || nonce || ciphertext).
    pub data: Vec<u8>,
    /// Monotonic sequence within the inbox.
    pub seq: u64,
}

/// A recipient's inbox: all their stored messages.
#[derive(BorshSerialize, BorshDeserialize, Default)]
pub struct Inbox {
    /// Stored messages in delivery order.
    pub messages: Vec<StoredMessage>,
}

/// Compute the recipient's inbox PDA.
pub fn inbox_pda(program_id: &Pubkey, recipient: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"mycelium", recipient.as_ref()], program_id)
}

entrypoint!(process_instruction);

/// Dispatch.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (tag, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        0 => deliver(program_id, accounts, rest),
        1 => burn(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn deliver(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    // Sender: signs (pays + authorizes the delivery), like the "from" of an email.
    let sender = next_account_info(it)?;
    // Recipient: the pubkey whose inbox receives the message. Does NOT need to
    // sign — anyone may deliver to an address (email semantics).
    let recipient = next_account_info(it)?;
    let inbox = next_account_info(it)?; // PDA inbox, must be writable
    let payer = next_account_info(it)?; // pays rent, signs (sender or a sponsor)
    let system_program = next_account_info(it)?;

    if !sender.is_signer {
        msg!("sender must sign to deliver");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_signer {
        msg!("payer must sign to pay for rent");
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (expected, bump) = inbox_pda(program_id, recipient.key);
    if inbox.key != &expected {
        msg!("inbox PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }

    // Load existing inbox (or start empty).
    let mut loaded = if inbox.lamports() > 0 && !inbox.data_is_empty() {
        match Inbox::try_from_slice(&inbox.data.borrow()) {
            Ok(v) => v,
            Err(_) => Inbox::default(),
        }
    } else {
        Inbox::default()
    };

    let seq = loaded.messages.len() as u64;
    loaded.messages.push(StoredMessage {
        from: sender.key.to_bytes(),
        data: data.to_vec(),
        seq,
    });

    let serialized = loaded
        .try_to_vec()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let space_needed = serialized.len();

    // If the account doesn't exist yet, create it sized + rent-funded for this
    // message in one shot (realloc cannot add rent, so init at full size).
    if inbox.lamports() == 0 {
        let rent = Rent::get()?;
        let min_bal = rent.minimum_balance(space_needed);
        invoke_signed(
            &system_instruction::create_account(
                payer.key,
                inbox.key,
                min_bal,
                space_needed as u64,
                program_id,
            ),
            &[payer.clone(), inbox.clone(), system_program.clone()],
            &[&[b"mycelium", recipient.key.as_ref(), &[bump]]],
        )?;
    } else if inbox.data_len() < space_needed {
        // Existing account too small (only grows across messages). Realloc with
        // rent top-up from the payer.
        let rent = Rent::get()?;
        let new_rent = rent.minimum_balance(space_needed);
        let lamports_diff = new_rent.saturating_sub(inbox.lamports());
        if lamports_diff > 0 {
            invoke_signed(
                &system_instruction::transfer(payer.key, inbox.key, lamports_diff),
                &[payer.clone(), inbox.clone(), system_program.clone()],
                &[],
            )?;
        }
        inbox.realloc(space_needed, false)?;
    }
    inbox.try_borrow_mut_data()?.copy_from_slice(&serialized);

    msg!("delivered msg {} to {} from {}", seq, recipient.key, sender.key);
    Ok(())
}

fn burn(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    if rest.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let idx = u64::from_le_bytes(rest[..8].try_into().unwrap());
    let it = &mut accounts.iter();
    let recipient = next_account_info(it)?;
    let inbox = next_account_info(it)?;

    if !recipient.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (expected, _) = inbox_pda(program_id, recipient.key);
    if inbox.key != &expected {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut loaded = Inbox::try_from_slice(&inbox.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if (idx as usize) < loaded.messages.len() {
        loaded.messages[idx as usize].data = Vec::new(); // empty = composted
    }
    let serialized = loaded
        .try_to_vec()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    inbox.try_borrow_mut_data()?.copy_from_slice(&serialized);
    msg!("burnt msg {} for {}", idx, recipient.key);
    Ok(())
}

/// Off-chain helper: parse an inbox account's messages.
pub fn parse_inbox(data: &[u8]) -> Result<Inbox, ProgramError> {
    Inbox::try_from_slice(data).map_err(|_| ProgramError::InvalidAccountData)
}
