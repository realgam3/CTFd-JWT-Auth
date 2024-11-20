import os
import jwt
from flask import jsonify
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse
from CTFd.utils.user import get_current_user
from flask import Blueprint, request, redirect, url_for, current_app as app, render_template

def load(app):
    jwt_auth_bp = Blueprint('jwt_auth', __name__, template_folder='templates')

    @jwt_auth_bp.route('/jwt_auth/login')
    def jwt_auth_route():
        redirect_url = request.args.get('redirect')
        if not redirect_url:
            return render_template('error.html', message='Redirect URL not provided'), 400

        # Validate the redirect URL
        if not is_safe_url(redirect_url):
            return render_template('error.html', message='Invalid redirect URL'), 400

        user = get_current_user()
        if not user:
            login_url = url_for('auth.login', next=request.full_path)
            return redirect(login_url)

        # user = get_current_user()
        # team = Teams.query.get(user.team_id)
        # team_name = team.name if team else None
        #
        # # Prepare the JWT payload with expiration
        # payload = {
        #     'username': user.name,
        #     'team_name': team_name,
        #     'exp': datetime.utcnow() + timedelta(minutes=5),
        #     'iat': datetime.utcnow()
        # }

        # # Prepare the JWT payload with expiration
        now = datetime.utcnow()
        payload = {
            "user_id": user.id,
            "team_id": user.team_id,
            'iat': now,
            'exp': now + timedelta(hours=5)
        }

        # Load the private key from an environment variable or secure location
        private_key = None

        # First, try to get the key from the configuration
        private_key_path = app.config.get('JWT_PRIVATE_KEY_PATH') or os.getenv('JWT_PRIVATE_KEY_PATH')
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as key_file:
                private_key = key_file.read()
        else:
            # Alternatively, try to get the key from an environment variable
            private_key = os.environ.get('JWT_PRIVATE_KEY') or os.getenv('JWT_PRIVATE_KEY')
            if private_key:
                private_key = private_key.encode()
            else:
                return render_template('error.html', message='Private key not configured'), 500

        # # Sign the JWT
        token = jwt.encode(payload, private_key, algorithm='RS256')

        # Append the JWT as a query parameter to the redirect URL
        parsed_url = urlparse(redirect_url)
        query_params = dict(request.args)
        query_params['jwt'] = token
        query_params.pop('redirect', None)
        new_query = urlencode(query_params, doseq=True)
        redirected_url = parsed_url._replace(query=new_query).geturl()

        return redirect(redirected_url)

    @jwt_auth_bp.route('/jwt_auth/key')
    def jwt_auth_public():
        public_key_path = app.config.get('JWT_PUBLIC_KEY_PATH') or os.getenv('JWT_PUBLIC_KEY_PATH')
        if not public_key_path or not os.path.exists(public_key_path):
            return render_template('error.html', message='Public key not configured'), 500

        with open(public_key_path, 'rb') as key_file:
            public_key = key_file.read()

        response = app.make_response(
            public_key,
        )
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = 'attachment; filename="public.pem"'
        return response

    app.register_blueprint(jwt_auth_bp)

def is_safe_url(target):
    from urllib.parse import urlparse

    allowed_domains = app.config.get('ALLOWED_REDIRECT_DOMAINS', '') or os.getenv('ALLOWED_REDIRECT_DOMAINS', '')
    allowed_domains = allowed_domains.split(',')
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and test_url.netloc in allowed_domains