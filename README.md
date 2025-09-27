# opensrc-website

CYSCOM VIT's leaderboard 

# Setup

### . Place a `.env` file

Format of `.env` file to be placed [here](./.env)

```env
START_ACT=3
END_ACT=8
CURRENT_ACT_YEAR=2025
SECRET_KEY=your-very-secure-secret-key-here
FIREBASE_STORAGE=your-project.appspot.com
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY_ID=your-private-key-id
FIREBASE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nYour private key here\n-----END PRIVATE KEY-----
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@your-project.iam.gserviceaccount.com
FIREBASE_CLIENT_ID=your-client-id
FIREBASE_CLIENT_X509_CERT_URL=https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-xxxxx%40your-project.iam.gserviceaccount.com
```

1. Start act - The number of the act to start from when displaying the leaderboard.
2. END act - current act number in the database
3. Current act year - field just used to show the year beside the name of the acts in the dropdown
4. Use a service account to manage db entries


# Development

## Run the project using 
```
python app.py
```
after installing dependencies using 
```
pip install -r requirements.txt
```

The project uses [Poetry](https://python-poetry.org/) to manage dependencies.

<details>
<summary>Why?</summary>
<br>
Poetry helps manage virtual environments easily.

It also pins versions of both dependencies and their dependencies recursively, unlike Pip. This means every package has an exact version and hash to check and download against.

With dependencies like `discord.py`, it became an issue since it's dependencies were not pinned and pip was installing the latest version, leading to many issues.
<br>

</details>

1.  Download `poetry` using Pip, or by following any of the other methods listed on their [website](https://python-poetry.org/docs/#installation)

```sh
pip install poetry
```

2. Create a virtual env and install all dependencies using poetry.

```sh
poetry install
```

    This will create and activate a virtual env. It will also install all dependencies from the poetry.lock file.

To add new dependencies:

```sh
poetry add package-name
```

Update it in the `requirements.txt` (**USING POETRY COMMANDS, DON'T EDIT IT MANUALLY**) file too. Even though we use poetry, having a usable requirements.txt file might be convient for others. It is also used to build the docker image, since having poetry installed makes the image larger (smaller image better). Since the requirements.txt file is kept up-to-date, the image can use `pip` to install it, without ever downloading or installing poetry.

```sh
poetry export -f requirements.txt -o requirements.txt
```

**MAKE SURE YOU ADD DEPENDENCIES USING POETRY FIRST, AND DO NOT USE PIP TO INSTALL ANY PACKAGE FOR THIS PROJECT**. This ensures the package's dependencies are also pinned in the `poetry.lock` file as well.
