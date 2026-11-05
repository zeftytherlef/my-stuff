# RUSOCIAL Snapchat Python library

A focused library for Snapchat Android **12.08.0.29**. It builds the requests, manages sessions and signs supported routes through [free.rusocial.io](https://free.rusocial.io/).

Release **r7** (`12.8.0.29.post6`) keeps the 16 actions below. The old general-purpose endpoint interface and unrelated services have been removed.

## Install and start

Requires Python 3.10 or newer. Extract the ZIP and run these commands inside its folder:

```text
python -m pip install --upgrade .
python examples/basic.py
```

The example asks for your RUSOCIAL API key and Snapchat login, then lists friends. It does not send anything or add anyone automatically. Open **docs.html** for the complete standalone guide.

```python
import getpass
from rusocial_snapchat import SnapchatClient

with SnapchatClient(getpass.getpass("RUSOCIAL API key: "),
                    session_file="my-session.json") as snap:
    if not snap.is_logged_in:
        snap.login(input("Snapchat username: "),
                   getpass.getpass("Snapchat password: "))
    for friend in snap.sync_friends():
        print(friend.username, friend.display_name)
```

The library fills device IDs, timestamps, tokens and request payloads. Your RUSOCIAL key goes only to the signer. Keep the session file private: it contains login tokens and local key material, but never your password or RUSOCIAL key. Use a separate session file for each account.

## Supported actions

| Python call | Purpose |
| --- | --- |
| `login(username, password)` | Log in and save the returned session |
| `verify_login(code, method="authenticator")` | Finish a two-factor challenge; also accepts `method="sms"` |
| `friends()` | Refresh and return friends |
| `sync_friends(full=False)` | Merge changes using saved sync tokens; `full=True` requests a fresh list |
| `quick_adds()` | Fetch Quick Add suggestions |
| `search_users(query)` | Search for users |
| `add_friend(username)` | Add a friend |
| `remove_friend(username)` | Remove a friend |
| `block_friend(username)` | Block a user |
| `unblock_friend(username)` | Unblock a user |
| `mute_friend(username)` | Mute a friend's story |
| `unmute_friend(username)` | Unmute a friend's story |
| `send_message(recipient, text)` | Send text in an existing one-to-one chat |
| `send_snap(recipient, filename, duration=10)` | Upload and send a photo or video |
| `post_story(filename, duration=10)` | Upload and post to My Story |
| `logout()` | Log out and clear the local login state |

`duration` and `full` are keyword-only arguments. Friend actions accept either a username or a returned `Friend` / `QuickAdd` object. Send recipients accept a username or `Friend`.

```python
for suggestion in snap.quick_adds():
    print(suggestion.username, suggestion.display_name, suggestion.reason)

snap.add_friend("friend_username")
snap.send_message("friend_username", "Hello!")
snap.send_snap("friend_username", "photo.jpg", duration=5)
snap.send_snap("friend_username", "clip.mp4")
sent = snap.post_story("photo.jpg", duration=10)
print(sent.message_id, sent.request_id)
```

Quick Adds does not add users or mark suggestions seen. Sync handles partial updates, renames and removals. `Friend` exposes `username`, `user_id` and `display_name`; `QuickAdd` also exposes `reason`. Friend changes return `ActionResult` with `action`, `friend` and `success`. Sends return `SentMessage` with `action`, `destination_id`, `message_id`, `request_id` and `success` after the server confirms the destination.

Messages and snaps require an existing one-to-one chat. If the library cannot find it, open a chat with that friend in Snapchat first. Group chats, creating new conversations, captions, stickers and mentions are not included.

Media accepts JPEG, PNG, or MP4 with one H.264 video track and optional AAC audio. Photos display for 1–10 seconds; videos use their own duration, up to 60 seconds. Files are limited to 32 MiB and 8192 pixels per dimension. My Story preserves your existing visibility settings.

## Sessions and verification

`snap.me` is the saved account; `snap.is_logged_in` checks local login state without contacting Snapchat. Access tokens refresh automatically when possible, but a revoked session requires login again. `snap.save_session("my-session.json")` enables persistence on an existing client. Use a `with` block or call `snap.close()` when finished.

```python
from rusocial_snapchat import LoginChallenge

try:
    snap.login(username, password)
except LoginChallenge as challenge:
    if challenge.kind != "two_factor_verification":
        raise
    method = "authenticator" if "authenticator" in challenge.methods else "sms"
    snap.verify_login(input("Verification code: "), method=method)
```

Other login challenges must be completed in Snapchat. Failed logins and pending verification are never treated as success.

## Errors and compatibility

Catch `AuthenticationError` for login failures, `SendError` for rejected or unconfirmed sends, and `SnapchatError` for other library errors. `RpcError` exposes the transport `code`, redacted server `details` and `path`.

For this version's password-login response, status **14** means invalid password for that username or email, **13** means account not found, and **12** means account not found or password incorrect. `AuthenticationError.status` and `.code` expose these results. These are endpoint response statuses, not gRPC status codes; unknown codes are not given guessed meanings.

Requests are not retried automatically. A connection failure can happen after Snapchat accepts a send, so check Snapchat before retrying to avoid duplicates.

The requests were checked against the supplied 12.08.0.29 Java and native code and tested offline, including real local TLS transport tests. **Live Snapchat login, sending and posting have not been verified.**

Send methods use the app's stateless request format over TLS. Media files use fresh AES encryption keys carried in the message metadata. The library does **not** implement the app's Fidelius/EEL end-to-end message encryption.

The default User-Agent is `Snapchat/12.08.0.29 (Pixel 6; Android 13#TP1A.221005.002#33; gzip)` and follows the configured device profile. The complete native app network header has not been captured. Local tests verify the Python client's headers and request bytes, not current server acceptance of this older app version.

## Updating older scripts

Install r7 from its extracted root folder with `python -m pip install --upgrade .`. Existing session files remain readable. Replace `snap.api`, `snap.services`, generic builders and raw `snap.request()` calls with the supported actions above. The package retains only 11 supporting routes and the schemas these actions need. Registration and Web routes remain blocked.

The website and signer must be deployed together with this release so the two native messaging routes are allowed. This repository's public download and standalone HTML documentation are generated by `tools/build_python_sdk.py`.

## Repository checks

```text
python -m pip install "./sdk/python[test]"
python -m unittest discover -s tests/python_sdk
python tools/build_python_sdk.py --check
```

The ZIP contains the installable package, example and standalone HTML guide. It excludes server source, signing keys, backups and local sessions.
