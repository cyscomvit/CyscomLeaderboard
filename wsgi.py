from app import app

# This is the WSGI entry point for Vercel
application = app

if __name__ == "__main__":
    from os import getenv
    port: int = int(getenv("PORT")) if getenv("PORT") else 5000
    debug = True if str(getenv("DEBUG")).casefold() == "true" else False
    print("Running")
    app.run(host="0.0.0.0", port=port, debug=debug)
