from app import app

# Export the app for Vercel
# Vercel will automatically handle the WSGI interface
if __name__ == "__main__":
    app.run()