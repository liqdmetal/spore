use borsh::BorshSerialize;
use mycelium_mailbox::{inbox_pda, parse_inbox, process_instruction, Inbox, StoredMessage};
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, tokio, BanksClient, ProgramTest};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

fn program_id() -> Pubkey {
    mycelium_mailbox::id()
}

async fn setup() -> (BanksClient, Keypair, Hash) {
    let mut pt = ProgramTest::default();
    pt.add_program(
        "mycelium_mailbox",
        program_id(),
        processor!(process_instruction),
    );
    pt.start().await
}

/// Submits `deliver(data)` into `recipient`'s inbox, paid + signed by `payer`.
async fn deliver(banks: &mut BanksClient, payer: &Keypair, bh: Hash, recipient: &Pubkey, data: &[u8]) {
    let (pda, _) = inbox_pda(&program_id(), recipient);
    let mut ix_data = vec![0u8]; // tag 0 = deliver
    ix_data.extend_from_slice(data);
    let ix = Instruction::new_with_bytes(
        program_id(),
        &ix_data,
        vec![
            AccountMeta::new(payer.pubkey(), true),               // sender (signer)
            AccountMeta::new(*recipient, false),                  // recipient
            AccountMeta::new(pda, false),                         // inbox PDA (writable)
            AccountMeta::new(payer.pubkey(), true),               // payer (signer)
            AccountMeta::new_readonly(system_program::id(), false),
        ],
    );
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[payer], bh);
    banks
        .process_transaction(tx)
        .await
        .expect("deliver must succeed");
}

/// Submits `burn(idx)` for `recipient`'s inbox. Returns Err(description) if the
/// transaction failed — the success path is what the old code could never
/// reach (audit H3: shrink mismatch panic in copy_from_slice).
async fn try_burn(
    banks: &mut BanksClient,
    payer: &Keypair,
    bh: Hash,
    recipient: &Keypair,
    idx: u64,
) -> Result<(), String> {
    let (pda, _) = inbox_pda(&program_id(), &recipient.pubkey());
    let mut ix_data = vec![1u8]; // tag 1 = burn
    ix_data.extend_from_slice(&idx.to_le_bytes());
    let ix = Instruction::new_with_bytes(
        program_id(),
        &ix_data,
        vec![
            AccountMeta::new(recipient.pubkey(), true), // recipient must sign
            AccountMeta::new(pda, false),
        ],
    );
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[payer, recipient], bh);
    banks
        .process_transaction(tx)
        .await
        .map(|_| ())
        .map_err(|e| format!("burn failed: {e}"))
}

async fn inbox(banks: &mut BanksClient, recipient: &Pubkey) -> Inbox {
    let (pda, _) = inbox_pda(&program_id(), recipient);
    let acct = banks
        .get_account(pda)
        .await
        .expect("get inbox account")
        .expect("inbox account must exist");
    parse_inbox(&acct.data).expect("inbox must parse")
}

// ---------------------------------------------------------------- pure tests

#[test]
fn pda_is_deterministic() {
    let program = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let (p1, b1) = inbox_pda(&program, &recipient);
    let (p2, b2) = inbox_pda(&program, &recipient);
    assert_eq!(p1, p2);
    assert_eq!(b1, b2);
    // Different recipient -> different PDA.
    let other = Pubkey::new_unique();
    let (p3, _) = inbox_pda(&program, &other);
    assert_ne!(p1, p3);
}

#[test]
fn inbox_roundtrip_via_borsh() {
    let mut inbox = Inbox::default();
    inbox.messages.push(StoredMessage {
        from: [7u8; 32],
        data: vec![0xE0, 1, 2, 3], // envelope kind + bytes
        seq: 0,
    });
    inbox.messages.push(StoredMessage {
        from: [9u8; 32],
        data: vec![0xE0, 4, 5],
        seq: 1,
    });

    let bytes = inbox.try_to_vec().expect("serialize");
    let parsed = parse_inbox(&bytes).expect("parse");
    assert_eq!(parsed.messages.len(), 2);
    assert_eq!(parsed.messages[0].data, vec![0xE0, 1, 2, 3]);
    assert_eq!(parsed.messages[1].from, [9u8; 32]);
    assert_eq!(parsed.messages[1].seq, 1);
}

#[test]
fn empty_inbox_parses() {
    let inbox = Inbox::default();
    let bytes = inbox.try_to_vec().expect("serialize");
    let parsed = parse_inbox(&bytes).expect("parse");
    assert!(parsed.messages.is_empty());
}

/// The core of the H3 fix, proven at the serialization layer: burning a message
/// SHRINKS the borsh serialization. The old code wrote the shorter bytes into
/// the unchanged (larger) account with copy_from_slice — a guaranteed length
/// mismatch panic, i.e. burn was bricked. commit() now reallocs down first.
#[test]
fn burn_shrinks_serialization() {
    let mut inbox = Inbox::default();
    inbox.messages.push(StoredMessage {
        from: [1u8; 32],
        data: vec![0xE1u8; 100],
        seq: 0,
    });
    let full_len = inbox.try_to_vec().expect("serialize").len();

    inbox.messages[0].data = Vec::new(); // what burn does
    let burnt = inbox.try_to_vec().expect("serialize");
    assert!(
        burnt.len() < full_len,
        "burnt serialization ({}) must be shorter than live ({}) — the old code wrote it into a {}-byte account and panicked",
        burnt.len(),
        full_len,
        full_len
    );
    // It still parses: exactly one tombstoned (empty-data) message remains.
    let parsed = parse_inbox(&burnt).expect("burnt inbox must parse");
    assert_eq!(parsed.messages.len(), 1);
    assert!(parsed.messages[0].data.is_empty());
}

/// Redelivering after a burn must GROW the serialization back — commit() must
/// handle the shrink-then-grow lifecycle, not just monotonic growth.
#[test]
fn redeliver_after_burn_regrows() {
    let mut inbox = Inbox::default();
    inbox.messages.push(StoredMessage {
        from: [1u8; 32],
        data: vec![0xE1u8; 100],
        seq: 0,
    });
    let initial = inbox.try_to_vec().expect("serialize").len();

    inbox.messages[0].data = Vec::new(); // burn
    let burnt = inbox.try_to_vec().expect("serialize").len();
    assert!(burnt < initial);

    inbox.messages.push(StoredMessage {
        from: [2u8; 32],
        data: vec![0xE1u8; 100],
        seq: 1,
    });
    let regrown = inbox.try_to_vec().expect("serialize").len();
    let msg1 = StoredMessage {
        from: [2u8; 32],
        data: vec![0xE1u8; 100],
        seq: 1,
    }
    .try_to_vec()
    .expect("serialize")
    .len();
    assert!(regrown > burnt);
    // Regrowth = burnt size + the second message's serialized size.
    assert_eq!(regrown, burnt + msg1);
    assert_eq!(regrown, initial - 100 + msg1);
}

// ---------------------------------------------------------------- bank tests

/// THE regression test for audit H3: deliver a message, then burn it. On the
/// old code the burn transaction ALWAYS failed (shrunken serialization written
/// into the unchanged account → length-mismatch panic) once any message with
/// data existed, making compost semantics unreachable on Solana.
#[tokio::test]
async fn burn_after_deliver_succeeds() {
    let (mut banks, payer, bh) = setup().await;
    let recipient = Keypair::new();

    deliver(
        &mut banks,
        &payer,
        bh,
        &recipient.pubkey(),
        b"0xE1 envelope bytes here",
    )
    .await;

    // Sanity: the message is there; record the on-chain account size.
    let (pda, _) = inbox_pda(&program_id(), &recipient.pubkey());
    let before_len = banks
        .get_account(pda)
        .await
        .unwrap()
        .expect("inbox must exist")
        .data
        .len();
    let before = inbox(&mut banks, &recipient.pubkey()).await;
    assert_eq!(before.messages.len(), 1);
    assert_eq!(before.messages[0].data, b"0xE1 envelope bytes here");

    // Burn it — this panicked on the old code.
    try_burn(&mut banks, &payer, bh, &recipient, 0)
        .await
        .expect("burn must succeed (old code: shrink mismatch panic, audit H3)");

    // The message is composted (empty data), and the account SHRANK.
    let after = inbox(&mut banks, &recipient.pubkey()).await;
    assert_eq!(after.messages.len(), 1);
    assert!(after.messages[0].data.is_empty());
    let after_len = banks.get_account(pda).await.unwrap().unwrap().data.len();
    assert!(
        after_len < before_len,
        "account data must shrink on burn ({} -> {})",
        before_len,
        after_len
    );
}

/// The full compost lifecycle: deliver, burn, deliver again. Exercises the
/// shrink-then-grow realloc path — the account must stay well-formed and the
/// tombstoned message must stay in place with its seq preserved.
#[tokio::test]
async fn deliver_after_burn_grows_back() {
    let (mut banks, payer, bh) = setup().await;
    let recipient = Keypair::new();

    deliver(&mut banks, &payer, bh, &recipient.pubkey(), b"first message body").await;
    try_burn(&mut banks, &payer, bh, &recipient, 0)
        .await
        .expect("burn must succeed");

    deliver(&mut banks, &payer, bh, &recipient.pubkey(), b"second message body").await;

    let inbox = inbox(&mut banks, &recipient.pubkey()).await;
    assert_eq!(inbox.messages.len(), 2);
    assert!(inbox.messages[0].data.is_empty(), "tombstone must remain");
    assert_eq!(inbox.messages[0].seq, 0);
    assert_eq!(inbox.messages[1].data, b"second message body");
    assert_eq!(inbox.messages[1].seq, 1);
}

/// Burning an out-of-range index must be a clean program error, not a panic.
#[tokio::test]
async fn burn_out_of_range_is_clean_error() {
    let (mut banks, payer, bh) = setup().await;
    let recipient = Keypair::new();

    deliver(&mut banks, &payer, bh, &recipient.pubkey(), b"only one").await;
    let res = try_burn(&mut banks, &payer, bh, &recipient, 5).await;
    assert!(res.is_err(), "out-of-range burn must fail cleanly");
}

/// Anyone may deliver (email semantics) — a third-party sender does not need
/// the recipient's key, only their pubkey.
#[tokio::test]
async fn third_party_delivery() {
    let (mut banks, payer, bh) = setup().await;
    let recipient = Pubkey::new_unique(); // does not sign, does not exist on chain

    deliver(&mut banks, &payer, bh, &recipient, b"from a stranger").await;

    let inbox = inbox(&mut banks, &recipient).await;
    assert_eq!(inbox.messages.len(), 1);
    assert_eq!(inbox.messages[0].from, payer.pubkey().to_bytes());
}
