"""A simple interactive example. The API key can be typed securely or read from RUSOCIAL_API_KEY."""
import getpass
import os

from rusocial_snapchat import LoginChallenge, RpcError, SnapchatClient, SnapchatError, __version__


def main():
    print('RUSOCIAL Snapchat library', __version__)
    try:
        api_key = os.environ.get('RUSOCIAL_API_KEY') or getpass.getpass('RUSOCIAL API key: ')
        with SnapchatClient(api_key=api_key, session_file='my-session.json') as snap:
            if not snap.is_logged_in:
                try:
                    snap.login(input('Snapchat username: '), getpass.getpass('Snapchat password: '))
                except LoginChallenge as challenge:
                    if challenge.kind != 'two_factor_verification':
                        raise
                    method = 'authenticator' if 'authenticator' in challenge.methods else 'sms'
                    snap.verify_login(input('Verification code: '), method=method)
            print('Logged in as', snap.me.username)
            for friend in snap.sync_friends():
                print(friend.username, friend.display_name)
        return 0
    except RpcError as error:
        print('Snapchat rejected the request:', error.code)
        if error.details:
            print('Server message:', error.details)
    except SnapchatError as error:
        print(error)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
