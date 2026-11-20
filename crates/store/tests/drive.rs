//! The drive's schema and statements, against a migrated database.
//!
//! Two properties carry the design and are the load-bearing tests here: the composite key
//! scopes every read to one account, and an attachment made from a drive object keeps its
//! digest when the object is deleted (there is no foreign key, on purpose).

use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::drive;
use sqlx::PgPool;
use uuid::Uuid;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn seed_account(pool: &PgPool, username: &str) -> String {
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

async fn seed_status(pool: &PgPool, account: &str) -> String {
    let id = nodus_server_core::Id::new().to_string();
    sqlx::query(
        "INSERT INTO status (id, account_id, content, visibility) \
         VALUES ($1, $2, 'a post with a picture', 'public')",
    )
    .bind(&id)
    .bind(account)
    .execute(pool)
    .await
    .expect("insert status");
    id
}

#[sqlx::test(migrations = "./migrations")]
async fn folder_tree_is_created_listed_renamed_moved_and_deleted(pool: PgPool) {
    let account = seed_account(&pool, "alice").await;

    let projects = drive::create_folder(&pool, &account, None, "Projects")
        .await
        .expect("create root folder");
    let drafts = drive::create_folder(&pool, &account, Some(projects.id), "Drafts")
        .await
        .expect("create child folder");
    let old = drive::create_folder(&pool, &account, Some(drafts.id), "2024")
        .await
        .expect("create grandchild folder");
    let photos = drive::create_folder(&pool, &account, None, "Photos")
        .await
        .expect("create second root");

    let all = drive::folders(&pool, &account).await.expect("list folders");
    assert_eq!(all.len(), 4);
    assert_eq!(drafts.parent_id, Some(projects.id));

    assert!(
        drive::rename_folder(&pool, &account, drafts.id, "Drafts 2025")
            .await
            .expect("rename")
    );
    let all = drive::folders(&pool, &account).await.expect("list folders");
    let renamed = all.iter().find(|f| f.id == drafts.id).unwrap();
    assert_eq!(renamed.name, "Drafts 2025");

    // A subtree move: the grandchild rides along, because only the root's parent changes.
    drive::move_folder(&pool, &account, drafts.id, Some(photos.id))
        .await
        .expect("move subtree under another root");
    let all = drive::folders(&pool, &account).await.expect("list folders");
    let moved = all.iter().find(|f| f.id == drafts.id).unwrap();
    assert_eq!(moved.parent_id, Some(photos.id));
    let child = all.iter().find(|f| f.id == old.id).unwrap();
    assert_eq!(child.parent_id, Some(drafts.id));

    // Moving to the root is a write, not a refusal.
    drive::move_folder(&pool, &account, drafts.id, None)
        .await
        .expect("move to root");
    let all = drive::folders(&pool, &account).await.expect("list folders");
    assert_eq!(
        all.iter().find(|f| f.id == drafts.id).unwrap().parent_id,
        None
    );

    // Deleting the subtree's root deletes everything under it and nothing beside it.
    let object = drive::create_object(
        &pool,
        &account,
        Some(old.id),
        "scan.png",
        "image/png",
        SHA_A,
        1_024,
    )
    .await
    .expect("create object in subtree");
    drive::move_folder(&pool, &account, drafts.id, Some(projects.id))
        .await
        .expect("re-nest the subtree");

    let deleted_digests = drive::delete_folder(&pool, &account, projects.id)
        .await
        .expect("delete subtree");
    assert_eq!(deleted_digests, vec![SHA_A.to_string()]);
    assert!(drive::folders(&pool, &account)
        .await
        .expect("list folders")
        .iter()
        .all(|f| f.id != projects.id && f.id != drafts.id && f.id != old.id));
    assert_eq!(
        drive::folders(&pool, &account).await.expect("list").len(),
        1,
        "the sibling root survives"
    );
    assert_eq!(
        drive::objects(&pool, &account, Some(old.id), 50, 0)
            .await
            .expect("list objects")
            .len(),
        0,
        "objects in the subtree went with it"
    );
    assert!(drive::object(&pool, &account, object.id)
        .await
        .expect("object")
        .is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_move_into_a_descendant_is_refused(pool: PgPool) {
    let account = seed_account(&pool, "alice").await;
    let root = drive::create_folder(&pool, &account, None, "root")
        .await
        .expect("root");
    let child = drive::create_folder(&pool, &account, Some(root.id), "child")
        .await
        .expect("child");
    let grandchild = drive::create_folder(&pool, &account, Some(child.id), "grandchild")
        .await
        .expect("grandchild");

    // Into itself, into a child, into a grandchild: all three are cycles.
    for target in [root.id, child.id, grandchild.id] {
        let refused = drive::move_folder(&pool, &account, root.id, Some(target)).await;
        assert!(
            matches!(refused, Err(drive::MoveError::Cycle)),
            "moving root under {target} must be refused"
        );
    }

    // Refused, not stored: the tree is exactly as it was.
    let all = drive::folders(&pool, &account).await.expect("list");
    assert_eq!(
        all.iter().find(|f| f.id == root.id).unwrap().parent_id,
        None
    );
    assert_eq!(
        all.iter().find(|f| f.id == child.id).unwrap().parent_id,
        Some(root.id)
    );

    // A move that is not a cycle still works, and a move to a missing parent is NotFound.
    drive::move_folder(&pool, &account, grandchild.id, Some(root.id))
        .await
        .expect("legal move");
    assert!(matches!(
        drive::move_folder(&pool, &account, child.id, Some(Uuid::now_v7())).await,
        Err(drive::MoveError::NotFound)
    ));
    assert!(matches!(
        drive::move_folder(&pool, &account, Uuid::now_v7(), None).await,
        Err(drive::MoveError::NotFound)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn the_composite_key_scopes_everything_by_account(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let bob = seed_account(&pool, "bob").await;

    let alice_folder = drive::create_folder(&pool, &alice, None, "shared")
        .await
        .expect("alice folder");
    let alice_object = drive::create_object(
        &pool,
        &alice,
        Some(alice_folder.id),
        "alice.png",
        "image/png",
        SHA_A,
        10,
    )
    .await
    .expect("alice object");

    // The same uuids under a second account are two rows, not a conflict.
    sqlx::query(
        "INSERT INTO drive_folder (account_id, id, parent_id, name) \
         VALUES ($1, $2, NULL, $3)",
    )
    .bind(&bob)
    .bind(alice_folder.id)
    .bind("bob's shared")
    .execute(&pool)
    .await
    .expect("the same folder uuid under another account");
    sqlx::query(
        "INSERT INTO drive_object \
         (account_id, id, folder_id, filename, mime_type, byte_size, sha256) \
         VALUES ($1, $2, $3, 'bob.png', 'image/png', 10, $4)",
    )
    .bind(&bob)
    .bind(alice_object.id)
    .bind(alice_folder.id)
    .bind(SHA_B)
    .execute(&pool)
    .await
    .expect("the same object uuid under another account");

    // Every read for Alice returns nothing of Bob's, and vice versa.
    let alice_folders = drive::folders(&pool, &alice).await.expect("list");
    assert_eq!(alice_folders.len(), 1);
    assert_eq!(alice_folders[0].name, "shared");

    let bob_folders = drive::folders(&pool, &bob).await.expect("list");
    assert_eq!(bob_folders.len(), 1);
    assert_eq!(bob_folders[0].name, "bob's shared");

    let alice_objects = drive::objects(&pool, &alice, Some(alice_folder.id), 50, 0)
        .await
        .expect("list");
    assert_eq!(alice_objects.len(), 1);
    assert_eq!(alice_objects[0].filename, "alice.png");

    let bob_objects = drive::objects(&pool, &bob, Some(alice_folder.id), 50, 0)
        .await
        .expect("list");
    assert_eq!(bob_objects.len(), 1);
    assert_eq!(bob_objects[0].filename, "bob.png");

    // A row of Bob's is invisible by id to Alice, and every write scoped by account fails
    // to touch it.
    assert!(drive::object(&pool, &alice, alice_object.id)
        .await
        .expect("object")
        .is_some_and(|row| row.filename == "alice.png"));
    assert!(drive::object(&pool, &bob, alice_object.id)
        .await
        .expect("object")
        .is_some_and(|row| row.filename == "bob.png"));
    // A write by Bob under the shared uuid lands on Bob's row only.
    assert!(
        drive::rename_object(&pool, &bob, alice_object.id, "renamed by bob")
            .await
            .expect("rename")
    );
    assert!(drive::object(&pool, &alice, alice_object.id)
        .await
        .expect("object")
        .is_some_and(|row| row.filename == "alice.png"));
    assert!(drive::object(&pool, &bob, alice_object.id)
        .await
        .expect("object")
        .is_some_and(|row| row.filename == "renamed by bob"));

    // A folder that is not in this account is not a legal parent. (Bob does hold a
    // folder under Alice's uuid — that is the two-rows property above — so the honest
    // probe is a uuid neither account has.)
    assert!(drive::create_folder(&pool, &bob, Some(Uuid::now_v7()), "x")
        .await
        .is_err());

    // Delete is scoped too: Alice deleting "her" uuid leaves Bob's row.
    assert!(drive::delete_object(&pool, &alice, alice_object.id)
        .await
        .expect("delete")
        .is_some());
    assert!(drive::object(&pool, &bob, alice_object.id)
        .await
        .expect("object")
        .is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn used_bytes_and_object_by_sha_are_per_account(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let bob = seed_account(&pool, "bob").await;

    let folder = drive::create_folder(&pool, &alice, None, "files")
        .await
        .expect("folder");

    assert_eq!(drive::used_bytes(&pool, &alice).await.expect("sum"), 0);
    assert_eq!(drive::used_bytes(&pool, &bob).await.expect("sum"), 0);

    let shared = drive::create_object(
        &pool,
        &alice,
        Some(folder.id),
        "one.png",
        "image/png",
        SHA_A,
        2_048,
    )
    .await
    .expect("first object");
    drive::create_object(&pool, &alice, None, "two.png", "image/png", SHA_B, 1_000)
        .await
        .expect("second object");
    drive::create_object(&pool, &bob, None, "bob.png", "image/png", SHA_A, 500)
        .await
        .expect("bob's object");

    assert_eq!(drive::used_bytes(&pool, &alice).await.expect("sum"), 3_048);
    assert_eq!(drive::used_bytes(&pool, &bob).await.expect("sum"), 500);

    // The dedupe candidate is this account's row with those bytes, never another's.
    let candidate = drive::object_by_sha(&pool, &alice, SHA_A)
        .await
        .expect("by sha")
        .expect("candidate");
    assert_eq!(candidate.id, shared.id);
    assert_eq!(candidate.filename, "one.png");
    assert_eq!(
        drive::object_by_sha(&pool, &bob, SHA_A)
            .await
            .expect("by sha")
            .expect("bob's candidate")
            .byte_size,
        500
    );
    assert!(drive::object_by_sha(&pool, &bob, SHA_B)
        .await
        .expect("by sha")
        .is_none());
    assert!(drive::object_by_sha(
        &pool,
        &alice,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    .await
    .expect("by sha")
    .is_none());

    // Visibility and state round-trip through the typed setters.
    assert!(
        drive::set_visibility(&pool, &alice, shared.id, drive::Visibility::UnlistedLink)
            .await
            .expect("visibility")
    );
    assert!(
        drive::set_state(&pool, &alice, shared.id, drive::ProcessingState::Ready)
            .await
            .expect("state")
    );
    let row = drive::object(&pool, &alice, shared.id)
        .await
        .expect("object")
        .expect("exists");
    assert_eq!(row.visibility, "unlisted_link");
    assert_eq!(row.processing_state, "ready");
    assert!(
        !drive::set_visibility(&pool, &bob, shared.id, drive::Visibility::Private)
            .await
            .expect("other account")
    );
    assert_eq!(
        drive::Visibility::parse("public_federated"),
        Some(drive::Visibility::PublicFederated)
    );
    assert_eq!(drive::Visibility::parse("everyone"), None);
    assert_eq!(
        drive::ProcessingState::parse("ready"),
        Some(drive::ProcessingState::Ready)
    );
}

/// The zero-copy path, and the one thing `stored_object_id` must not do: cascade.
#[sqlx::test(migrations = "./migrations")]
async fn attach_object_copies_the_digest_and_outlives_the_object(pool: PgPool) {
    let alice = seed_account(&pool, "alice").await;
    let bob = seed_account(&pool, "bob").await;
    let status_id = seed_status(&pool, &alice).await;

    let object = drive::create_object(&pool, &alice, None, "photo.jpg", "image/jpeg", SHA_A, 4_096)
        .await
        .expect("object");
    drive::set_state(&pool, &alice, object.id, drive::ProcessingState::Ready)
        .await
        .expect("ready");

    let attachment_id = drive::attach_object(
        &pool,
        &alice,
        object.id,
        Some(&status_id),
        "a cat on a keyboard",
        Some("0.5,0.25"),
        Some("LKO2?U%2Tw=w]~RBVZRi};RPxuwH"),
    )
    .await
    .expect("attach")
    .expect("object exists");

    let (digest, size, content_type, description, stored, state, blurhash, meta): (
        String,
        i64,
        String,
        String,
        Option<Uuid>,
        String,
        Option<String>,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT digest, size, content_type, description, stored_object_id, processing_state, \
                blurhash, meta \
           FROM media_attachment WHERE id = $1",
    )
    .bind(&attachment_id)
    .fetch_one(&pool)
    .await
    .expect("attachment row");

    assert_eq!(
        digest, object.sha256,
        "the attachment carries the object's digest"
    );
    assert_eq!(size, 4_096);
    assert_eq!(content_type, "image/jpeg");
    assert_eq!(description, "a cat on a keyboard");
    assert_eq!(stored, Some(object.id));
    assert_eq!(state, "ready");
    assert_eq!(blurhash.as_deref(), Some("LKO2?U%2Tw=w]~RBVZRi};RPxuwH"));
    assert_eq!(meta["focus"], "0.5,0.25");
    assert_eq!(meta.get("url"), None);

    // A second account cannot attach Alice's object.
    assert!(
        drive::attach_object(&pool, &bob, object.id, None, "", None, None)
            .await
            .expect("attach as bob")
            .is_none()
    );

    // Deleting the drive object must not touch the post's attachment: no foreign key.
    assert_eq!(
        drive::delete_object(&pool, &alice, object.id)
            .await
            .expect("delete object")
            .as_deref(),
        Some(SHA_A)
    );
    let survived: (String, Option<String>) =
        sqlx::query_as("SELECT digest, status_id FROM media_attachment WHERE id = $1")
            .bind(&attachment_id)
            .fetch_one(&pool)
            .await
            .expect("attachment survives the drive delete");
    assert_eq!(survived.0, SHA_A);
    assert_eq!(survived.1.as_deref(), Some(status_id.as_str()));

    // Dropping the whole folder is no different.
    let folder = drive::create_folder(&pool, &alice, None, "folder")
        .await
        .expect("folder");
    let filed = drive::create_object(
        &pool,
        &alice,
        Some(folder.id),
        "b.png",
        "image/png",
        SHA_B,
        8,
    )
    .await
    .expect("object");
    let filed_attachment = drive::attach_object(&pool, &alice, filed.id, None, "", None, None)
        .await
        .expect("attach")
        .expect("exists");
    drive::delete_folder(&pool, &alice, folder.id)
        .await
        .expect("delete folder");
    assert!(
        sqlx::query_scalar::<_, String>("SELECT digest FROM media_attachment WHERE id = $1")
            .bind(&filed_attachment)
            .fetch_optional(&pool)
            .await
            .expect("attachment survives the folder delete")
            .is_some()
    );
}
