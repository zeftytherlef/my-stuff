"""Friend deltas and on-demand suggestions used by Android 12.08.0.29."""
from __future__ import annotations

from .errors import ActionError, PayloadError
from .models import unix_time_ms
from .session import Friend, QuickAdd


def _rows(result, field):
    value = result.get(field, [])
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ActionError('Snapchat returned an invalid friend list.')
    return value


def _string(row, *fields):
    for field in fields:
        value = row.get(field)
        if value is not None and not isinstance(value, str):
            raise ActionError('Snapchat returned an invalid friend record.')
        if value:
            return value
    return ''


def _merge(existing, rows, *, full=False):
    # Use user IDs to match partial-column updates and username changes. Keep
    # opaque fields (including Fidelius information) for subsequent deltas.
    merged = {} if full else {key: dict(value) for key, value in existing.items()}
    for row in rows:
        username = _string(row, 'mutable_username', 'name', 'username')
        user_id = _string(row, 'user_id')
        if not username and not user_id:
            raise ActionError('Snapchat returned a friend record without an identity.')
        key = next((k for k, v in merged.items() if user_id and v.get('user_id') == user_id), username)
        previous = merged.pop(key, {})
        value = {**previous, **row}
        username = username or _string(previous, 'mutable_username', 'name', 'username')
        # NX6.type uses LX6: BLOCKED=2, DELETED=3. These are removals,
        # including tombstones containing just user_id and type.
        if value.get('type') in (2, 3):
            continue
        if not username:
            raise ActionError('A partial friend update needs a full sync first.')
        value['name'] = username
        if 'mutable_username' in value:
            value['mutable_username'] = username
        merged[username] = value
    return merged


class SocialActions:
    def sync_friends(self, *, full: bool = False) -> list[Friend]:
        """Merge server changes and return friends. full=True resets sync tokens."""
        if type(full) is not bool:
            raise PayloadError('full must be True or False.')
        state = self._state
        requested_full = full or not state.friends_sync_token
        result = self._account_request('/ami/friends', self._account_payload(
            friends_request={
                'friends_sync_token': '' if full else state.friends_sync_token,
                'added_friends_sync_token': '' if full else state.added_friends_sync_token,
                'request_token_only': False,
            }, is_post_login_request=False))
        mode = result.get('friends_sync_type', 'full' if requested_full else 'partial')
        added_mode = result.get('added_friends_sync_type', 'aPartial')
        if mode not in ('full', 'partial', 'token_only') or added_mode not in ('aFull', 'aPartial'):
            raise ActionError('Snapchat returned an unknown friend sync type.')
        if mode == 'full' and 'friends' not in result:
            raise ActionError('Snapchat returned an incomplete full friend sync.')
        tokens = [result.get('friends_sync_token', '' if full else state.friends_sync_token),
                  result.get('added_friends_sync_token', '' if full else state.added_friends_sync_token)]
        if any(not isinstance(token, str) for token in tokens):
            raise ActionError('Snapchat returned an invalid friend sync token.')
        # Old session files contain only the public Friend objects.
        existing = {
            name: {'name': f.username, 'user_id': f.user_id, 'display': f.display_name}
            for name, f in state.friends.items()}
        existing.update(state.friend_records)
        records = existing if mode == 'token_only' else _merge(
            existing, _rows(result, 'friends'), full=mode == 'full')
        if mode != 'token_only':
            records = _merge(records, _rows(result, 'partial_friends'))
        added = _merge(state.added_friend_records, _rows(result, 'added_friends'), full=added_mode == 'aFull')
        friends = {name: self._friend(row, name) for name, row in records.items()}
        # Validate the entire response before changing either list or token.
        state.friend_records, state.added_friend_records = records, added
        state.friends = friends
        state.friends_sync_token, state.added_friends_sync_token = tokens
        self._save_session()
        return list(friends.values())

    def friends(self) -> list[Friend]:
        """Refresh and return friends; saved sync tokens are managed automatically."""
        return self.sync_friends()

    def quick_adds(self) -> list[QuickAdd]:
        """Fetch Quick Add suggestions without marking them seen or adding anyone."""
        # CallableC11101Uih case 1 constructs this list request;
        # C33349oV5 dispatches ON_DEMAND to this route via C34941phh.
        started_at = unix_time_ms()
        result = self._account_request('/suggest_friend_on_demand', self._account_payload(
            action='list', last_sync_timestamp=self._state.quick_adds_updated_at_ms,
            suggested_friend_ranking_tweak=0, impression_id=0, impression_time_ms=0))
        if 'suggested_friend_results_v2' not in result and 'suggested_friend_results' not in result:
            raise ActionError('Snapchat returned an incomplete Quick Add response.')
        legacy = _rows(result, 'suggested_friend_results')
        rows = _rows(result, 'suggested_friend_results_v2') if 'suggested_friend_results_v2' in result else legacy
        reasons = {_string(row, 'id', 'user_id'): _string(row, 'suggest_reason_display', 'suggest_reason') for row in legacy}
        suggestions = {}
        for row in rows:
            if row.get('is_hidden') is True:
                continue
            username = _string(row, 'mutable_username', 'username', 'name')
            user_id = _string(row, 'userId', 'user_id', 'id')
            if not username:
                raise ActionError('Snapchat returned a Quick Add without a username.')
            suggestion = QuickAdd(username, user_id, _string(row, 'display_name', 'display'),
                                  _string(row, 'suggest_reason_display', 'suggest_reason') or reasons.get(user_id, ''),
                                  _string(row, 'metadata'))
            suggestions[user_id or username] = suggestion
        self._state.quick_adds_updated_at_ms = started_at
        self._save_session()
        return list(suggestions.values())
