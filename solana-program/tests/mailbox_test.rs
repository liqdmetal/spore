use mycelium_mailbox::{inbox_pda, parse_inbox, Inbox, StoredMessage};
use borsh::BorshSerialize;
use solana_program::pubkey::Pubkey;

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
