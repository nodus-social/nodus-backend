use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::polls::{self, NewPoll};
use nodus_server_store::statuses::{self, NewStatus};
use sqlx::PgPool;

async fn create_account(pool: &PgPool, username: &str) -> String {
    accounts::insert(
        pool,
        &NewAccount {
            username,
            display_name: username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert account")
    .id
}

/// A local status with two options, returning its poll id.
async fn create_poll(pool: &PgPool, account_id: &str, multiple: bool) -> String {
    let status_id = Id::new().to_string();
    let poll_id = format!("{status_id}:poll");
    let options = vec!["tea".to_owned(), "coffee".to_owned()];
    statuses::create_with_poll(
        pool,
        &NewStatus {
            id: &status_id,
            account_id,
            content: "which one",
            content_html: "<p>which one</p>",
            content_source: Some("which one"),
            content_format: "html",
            spoiler_text: "",
            visibility: "public",
            sensitive: false,
            in_reply_to_id: None,
            in_reply_to_account_id: None,
            reblog_of_id: None,
            language: Some("en"),
        },
        &[],
        &[],
        &[],
        Some(&NewPoll {
            id: &poll_id,
            status_id: &status_id,
            options: &options,
            multiple,
            hide_totals: false,
            expires_at: None,
        }),
    )
    .await
    .expect("insert status and poll");
    poll_id
}

/// `poll_vote`'s primary key is `(poll_id, account_id, option_index)`, not
/// `(poll_id, account_id)`; a multiple-choice poll therefore needs both rows to survive.
#[sqlx::test(migrations = "./migrations")]
async fn one_option_at_a_time_keeps_single_choice_but_adds_multiple_choice(pool: PgPool) {
    let author = create_account(&pool, "author").await;
    let voter = create_account(&pool, "voter").await;

    let single = create_poll(&pool, &author, false).await;
    assert!(
        polls::vote_option(&pool, &single, &voter, 0)
            .await
            .expect("first single choice"),
        "the first choice is a new row"
    );
    assert!(
        !polls::vote_option(&pool, &single, &voter, 1)
            .await
            .expect("second single choice"),
        "a single-choice poll keeps the first answer"
    );
    assert_eq!(
        polls::own_votes(&pool, &single, &voter)
            .await
            .expect("read single votes"),
        vec![0]
    );

    let multiple = create_poll(&pool, &author, true).await;
    for option in [0, 1] {
        assert!(
            polls::vote_option(&pool, &multiple, &voter, option)
                .await
                .expect("multiple choice"),
            "a multiple-choice poll accepts each option"
        );
    }
    assert!(
        !polls::vote_option(&pool, &multiple, &voter, 1)
            .await
            .expect("repeat multiple choice"),
        "the same option is not counted twice"
    );
    assert_eq!(
        polls::own_votes(&pool, &multiple, &voter)
            .await
            .expect("read multiple votes"),
        vec![0, 1]
    );
    assert_eq!(
        polls::voters_count(&pool, &multiple)
            .await
            .expect("read voters"),
        1,
        "two options from one actor are one voter"
    );
}
