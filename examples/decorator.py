def ctfd_authorize():
    def decor(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            token = request.args.get("jwt")
            if token:
                payload = jwt.decode(token, JWT_PUBLIC_TOKEN, algorithms=["RS256"],
                                     options={"verify_iat": False, "verify_exp": False})
                session["team_id"] = str(payload.get("team_id"))
                session["user_id"] = str(payload.get("user_id"))
                return redirect(request.url.split("?")[0])

            if not session.get("team_id") or not session.get("user_id"):
                return redirect(
                    f"https://{CTF_HOST}/jwt_auth/login?{urlencode({'redirect': request.url})}")

            return func(*args, **kwargs)

        return inner

    return decor

